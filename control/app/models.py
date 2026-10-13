"""SQLAlchemy-Datenmodell der Control Plane (Leitfaden Abschnitt 4.3)."""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class DeviceStatus(str, enum.Enum):
    """Zustandsautomat (R12): active -> rotating -> active/revoked."""
    ACTIVE = "active"
    ROTATING = "rotating"
    REVOKED = "revoked"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(32), default="student")
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    devices: Mapped[list["Device"]] = relationship(back_populates="user")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    label: Mapped[str] = mapped_column(String(255))
    pubkey: Mapped[str] = mapped_column(String(64), unique=True)  # Public Key -> DB (Privater Key nie!)
    wg_ip: Mapped[str] = mapped_column(String(32), unique=True)  # z. B. 10.9.0.42
    status: Mapped[str] = mapped_column(String(16), default=DeviceStatus.ACTIVE.value)

    user: Mapped["User"] = relationship(back_populates="devices")


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)  # z. B. "app"
    ip: Mapped[str] = mapped_column(String(32))                # z. B. 192.168.30.10
    port: Mapped[int] = mapped_column(Integer)                  # z. B. 443
    nft_set: Mapped[str] = mapped_column(String(64))            # z. B. "svc_app_clients"


class Policy(Base):
    """Kriterium der kriterienbasierten Autorisierung: user x service -> allowed."""

    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("user_id", "service_id"),)

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), primary_key=True)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)


class Token(Base):
    """Enrollment-Token: einmalig und mit Ablaufdatum (Leitfaden 5.1)."""

    __tablename__ = "tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped["User"] = relationship()
