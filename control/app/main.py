"""FastAPI-Control-Plane (PDP) — CRUD, Enrollment, Rotation, Widerruf.

Lebenszyklus (Leitfaden 5): Enrollment (Login/Token -> Keygenerierung ->
Peer + nft-Set-Eintrag -> einmaliger Profil-Download), Rotation (atomarer
Peer-Ersatz), Widerruf (Peer löschen + Sets leeren).
Admin-Endpunkte sind durch X-Admin-Token geschützt (bewusst kein IdP,
dokumentierter Scope-Ausschluss).
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app import policy
from app.gateway import GatewayClient, GatewayError
from app.models import Base, Device, Policy, Service, Token, User
from app.wgrender import client_profile, generate_keypair, qr_png

DB_PATH = os.environ.get("DB_PATH", "data/ztna.db")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:9090")
WG_GATEWAY_IP = os.environ.get("WG_GATEWAY_IP", "10.9.0.1")
WG_CLIENTS_FROM = os.environ.get("WG_CLIENTS_FROM", "10.9.0.10")
ENDPOINT_HOST = os.environ.get("ENDPOINT_HOST", "")
ENDPOINT_PORT = int(os.environ.get("ENDPOINT_PORT", "51820"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
MAX_DEVICES_PER_USER = int(os.environ.get("MAX_DEVICES_PER_USER", "3"))
TOKEN_TTL_HOURS = int(os.environ.get("TOKEN_TTL_HOURS", "24"))

engine = create_engine(
    f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
gateway = GatewayClient(GATEWAY_URL)
_gateway_pubkey_cache: str | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="ZTNA Control Plane", lifespan=lifespan)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_admin(x_admin_token: str = Header(default="")) -> None:
    if not ADMIN_TOKEN or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="invalid admin token")


# ---------------------------------------------------------------- Schemas


class UserIn(BaseModel):
    email: EmailStr
    role: str = Field(default="student", pattern="^(student|admin)$")


class ServiceIn(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    ip: str
    port: int = Field(gt=0, lt=65536)
    nft_set: str = Field(pattern=r"^svc_[a-z][a-z0-9_]*_clients$")


class PolicyIn(BaseModel):
    user_id: int
    service_id: int
    allowed: bool


class TokenIn(BaseModel):
    user_id: int
    ttl_hours: int = TOKEN_TTL_HOURS


class EnrollIn(BaseModel):
    label: str = Field(min_length=1, max_length=255)


# ---------------------------------------------------------------- Helpers


def get_object(db: Session, model, obj_id: int):
    obj = db.get(model, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail=f"{model.__name__} {obj_id} not found")
    return obj


def next_free_wg_ip(db: Session) -> str:
    used = set(db.scalars(select(Device.wg_ip)).all())
    prefix = WG_CLIENTS_FROM.rsplit(".", 1)[0]
    start = int(WG_CLIENTS_FROM.rsplit(".", 1)[1])
    for host in range(start, 255):
        candidate = f"{prefix}.{host}"
        if candidate not in used:
            return candidate
    raise HTTPException(status_code=503, detail="WireGuard-Adressbereich erschöpft")


def service_client_ips(db: Session, svc: Service) -> list[str]:
    """Tunnel-IPs aller Geräte, die für diesen Dienst autorisiert sind (R11).

    Kriterien: user.active AND policy.allowed AND device.status == active.
    """
    rows = db.execute(
        select(Device.wg_ip)
        .join(User, Device.user_id == User.id)
        .join(Policy, (Policy.user_id == User.id) & (Policy.service_id == svc.id))
        .where(User.active.is_(True), Policy.allowed.is_(True), Device.status == policy.STATUS_ACTIVE)
    ).scalars().all()
    return sorted(rows)


def sync_service(db: Session, svc: Service) -> None:
    try:
        gateway.put_service_clients(svc.nft_set, service_client_ips(db, svc))
    except GatewayError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


def sync_all_services(db: Session) -> None:
    for svc in db.scalars(select(Service)).all():
        sync_service(db, svc)


def build_profile(db: Session, user: User) -> str:
    services = db.execute(
        select(Service.ip, Service.port)
        .join(Policy, (Policy.service_id == Service.id) & (Policy.user_id == user.id))
        .where(Policy.allowed.is_(True))
    ).all()
    return services


def gateway_pubkey() -> str:
    """Public Key des Gateways (wg0) — gecached, für Client-Profile nötig."""
    global _gateway_pubkey_cache
    if _gateway_pubkey_cache is None:
        try:
            _gateway_pubkey_cache = gateway.get_pubkey()
        except GatewayError as exc:
            raise HTTPException(status_code=502, detail=f"Gateway-Pubkey nicht abrufbar: {exc}") from exc
    return _gateway_pubkey_cache


def deliver_device(db: Session, device: Device, private_key: str, format: str) -> Response:
    """Einmaliger Profil-Download: Datei, QR oder JSON (privater Schlüssel nur hier)."""
    services = build_profile(db, device.user)
    profile = client_profile(
        private_key=private_key,
        wg_ip=device.wg_ip,
        gateway_pubkey=gateway_pubkey(),
        endpoint_host=ENDPOINT_HOST,
        endpoint_port=ENDPOINT_PORT,
        services=[(ip, port) for ip, port in services],
    )
    if format == "conf":
        return PlainTextResponse(
            profile,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="wg-{device.id}.conf"'},
        )
    if format == "qr":
        return Response(qr_png(profile), media_type="image/png")
    return JSONResponse(
        {
            "device_id": device.id,
            "wg_ip": device.wg_ip,
            "status": device.status,
            "profile": profile,
            "hint": "Privater Schlüssel nur in dieser Antwort — nicht erneut abrufbar.",
        }
    )


# ---------------------------------------------------------------- Health


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------- Admin: CRUD


@app.post("/users", status_code=201, dependencies=[Depends(require_admin)])
def create_user(payload: UserIn, db: Session = Depends(get_db)) -> dict:
    if db.scalar(select(func.count()).where(User.email == payload.email)):
        raise HTTPException(status_code=409, detail="email already exists")
    user = User(email=payload.email, role=payload.role, active=True)
    db.add(user)
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role, "active": user.active}


@app.get("/users", dependencies=[Depends(require_admin)])
def list_users(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {"id": u.id, "email": u.email, "role": u.role, "active": u.active}
        for u in db.scalars(select(User)).all()
    ]


@app.post("/services", status_code=201, dependencies=[Depends(require_admin)])
def create_service(payload: ServiceIn, db: Session = Depends(get_db)) -> dict:
    if db.scalar(select(func.count()).where(Service.name == payload.name)):
        raise HTTPException(status_code=409, detail="service already exists")
    svc = Service(name=payload.name, ip=payload.ip, port=payload.port, nft_set=payload.nft_set)
    db.add(svc)
    db.commit()
    return {"id": svc.id, "name": svc.name, "ip": svc.ip, "port": svc.port, "nft_set": svc.nft_set}


@app.get("/services", dependencies=[Depends(require_admin)])
def list_services(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {"id": s.id, "name": s.name, "ip": s.ip, "port": s.port, "nft_set": s.nft_set}
        for s in db.scalars(select(Service)).all()
    ]


@app.put("/policies", dependencies=[Depends(require_admin)])
def put_policy(payload: PolicyIn, db: Session = Depends(get_db)) -> dict:
    get_object(db, User, payload.user_id)
    svc = get_object(db, Service, payload.service_id)
    pol = db.get(Policy, (payload.user_id, payload.service_id))
    if pol is None:
        pol = Policy(user_id=payload.user_id, service_id=payload.service_id, allowed=payload.allowed)
        db.add(pol)
    else:
        pol.allowed = payload.allowed
    db.commit()
    sync_service(db, svc)  # Autorisierungsänderung wirkt sofort im nft-Set
    return {"user_id": pol.user_id, "service_id": pol.service_id, "allowed": pol.allowed}


@app.post("/tokens", status_code=201, dependencies=[Depends(require_admin)])
def create_token(payload: TokenIn, db: Session = Depends(get_db)) -> dict:
    get_object(db, User, payload.user_id)
    token = Token(
        id=str(uuid.uuid4()),
        user_id=payload.user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=payload.ttl_hours),
        used=False,
    )
    db.add(token)
    db.commit()
    return {"token": token.id, "user_id": token.user_id, "expires_at": token.expires_at.isoformat()}


@app.get("/devices", dependencies=[Depends(require_admin)])
def list_devices(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": d.id,
            "user_id": d.user_id,
            "label": d.label,
            "pubkey": d.pubkey,
            "wg_ip": d.wg_ip,
            "status": d.status,
        }
        for d in db.scalars(select(Device)).all()
    ]


# ---------------------------------------------------------------- Enrollment (5.1)


@app.post("/enroll/{token_id}")
def enroll(
    token_id: str,
    payload: EnrollIn,
    format: str = Query(default="json", pattern="^(json|conf|qr)$"),
    db: Session = Depends(get_db),
) -> Response:
    token = db.get(Token, token_id)
    if token is None or token.used or token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="token ungültig, abgelaufen oder bereits benutzt")
    user = get_object(db, User, token.user_id)

    active_count = db.scalar(
        select(func.count()).where((Device.user_id == user.id) & (Device.status == policy.STATUS_ACTIVE))
    )
    decision = policy.evaluate(
        user_active=user.active,
        policy_allowed=True,
        device_status=policy.STATUS_ACTIVE,
        active_device_count=active_count,
        max_devices=MAX_DEVICES_PER_USER,
    )
    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.reason)

    keys = generate_keypair()
    device = Device(
        user_id=user.id,
        label=payload.label,
        pubkey=keys.public,
        wg_ip=next_free_wg_ip(db),
        status=policy.STATUS_ACTIVE,
    )
    db.add(device)
    db.commit()

    try:
        gateway.put_peer(device.id, device.pubkey, device.wg_ip)
        sync_all_services(db)
    except GatewayError as exc:
        db.delete(device)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    token.used = True  # Token erst nach erfolgreichem Enrollment verbrauchen
    db.commit()
    return deliver_device(db, device, keys.private, format)


# ---------------------------------------------------------------- Rotation & Widerruf (5.4)


@app.post("/devices/{device_id}/rotate", dependencies=[Depends(require_admin)])
def rotate_device(
    device_id: int,
    format: str = Query(default="json", pattern="^(json|conf|qr)$"),
    db: Session = Depends(get_db),
) -> Response:
    device = get_object(db, Device, device_id)
    if not policy.can_transition(device.status, policy.STATUS_ROTATING):
        raise HTTPException(status_code=409, detail=f"Rotation aus Status '{device.status}' nicht erlaubt")

    device.status = policy.STATUS_ROTATING
    db.commit()

    keys = generate_keypair()
    try:
        gateway.put_peer(device.id, keys.public, device.wg_ip)  # atomarer Peer-Ersatz
    except GatewayError as exc:
        device.status = policy.STATUS_ACTIVE  # alter Peer gilt unangetastet weiter
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    device.pubkey = keys.public
    device.status = policy.STATUS_ACTIVE  # alter Key ist mit dem Ersetzen sofort ungültig
    db.commit()
    return deliver_device(db, device, keys.private, format)


@app.post("/devices/{device_id}/revoke", dependencies=[Depends(require_admin)])
def revoke_device(device_id: int, db: Session = Depends(get_db)) -> dict:
    device = get_object(db, Device, device_id)
    if not policy.can_transition(device.status, policy.STATUS_REVOKED):
        raise HTTPException(status_code=409, detail=f"Widerruf aus Status '{device.status}' nicht erlaubt")

    device.status = policy.STATUS_REVOKED
    db.commit()
    try:
        gateway.delete_peer(device.id)   # Peer weg -> Tunnel stirbt
        sync_all_services(db)            # Set-Elemente der autorisierten Dienste weg
    except GatewayError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"id": device.id, "status": device.status}
