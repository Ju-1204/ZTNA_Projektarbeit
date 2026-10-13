"""Tests für die kriterienbasierte Autorisierung (policy.py)."""

import unittest

from app import policy


class EvaluateTest(unittest.TestCase):
    def test_all_criteria_met_allows(self):
        d = policy.evaluate(
            user_active=True,
            policy_allowed=True,
            device_status=policy.STATUS_ACTIVE,
            active_device_count=1,
            max_devices=3,
        )
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, "ok")

    def test_inactive_user_denied(self):
        d = policy.evaluate(
            user_active=False, policy_allowed=True,
            device_status=policy.STATUS_ACTIVE, active_device_count=0, max_devices=3,
        )
        self.assertFalse(d.allowed)

    def test_no_policy_denied(self):
        d = policy.evaluate(
            user_active=True, policy_allowed=False,
            device_status=policy.STATUS_ACTIVE, active_device_count=0, max_devices=3,
        )
        self.assertFalse(d.allowed)
        self.assertIn("policy", d.reason)

    def test_non_active_device_denied(self):
        for status in (policy.STATUS_ROTATING, policy.STATUS_REVOKED):
            d = policy.evaluate(
                user_active=True, policy_allowed=True,
                device_status=status, active_device_count=0, max_devices=3,
            )
            self.assertFalse(d.allowed, status)

    def test_device_limit_reached_denied(self):
        d = policy.evaluate(
            user_active=True, policy_allowed=True,
            device_status=policy.STATUS_ACTIVE, active_device_count=3, max_devices=3,
        )
        self.assertFalse(d.allowed)
        self.assertIn("limit", d.reason)

    def test_limit_not_reached_allows(self):
        d = policy.evaluate(
            user_active=True, policy_allowed=True,
            device_status=policy.STATUS_ACTIVE, active_device_count=2, max_devices=3,
        )
        self.assertTrue(d.allowed)


class TransitionTest(unittest.TestCase):
    def test_allowed_transitions(self):
        for old, new in [
            ("active", "rotating"),
            ("rotating", "active"),
            ("active", "revoked"),
            ("rotating", "revoked"),
        ]:
            self.assertTrue(policy.can_transition(old, new), (old, new))

    def test_forbidden_transitions(self):
        for old, new in [
            ("revoked", "active"),     # Widerruf ist endgültig
            ("revoked", "revoked"),    # idempotent wäre denkbar, bewusst verboten
            ("revoked", "rotating"),
            ("active", "active"),
        ]:
            self.assertFalse(policy.can_transition(old, new), (old, new))


if __name__ == "__main__":
    unittest.main()
