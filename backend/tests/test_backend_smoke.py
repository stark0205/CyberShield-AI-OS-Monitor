import os
import sys
import unittest
from pathlib import Path

from pydantic import ValidationError

os.environ["JWT_SECRET"] = "test-only-jwt-secret-with-at-least-32-bytes"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth.token import make_token, read_token
from main import health
from models.schemas import LoginIn


class BackendSmokeTests(unittest.TestCase):
    def test_health_response(self):
        self.assertEqual(health(), {"ok": True, "msg": "CyberShield AI running"})

    def test_login_requires_username_and_password(self):
        with self.assertRaises(ValidationError):
            LoginIn(uname="analyst")

    def test_token_round_trip(self):
        token = make_token(41, "analyst")
        self.assertEqual(read_token(token)["uid"], 41)
        self.assertEqual(read_token(token)["uname"], "analyst")

    def test_invalid_token_is_rejected(self):
        self.assertIsNone(read_token("not-a-valid-token"))


if __name__ == "__main__":
    unittest.main()
