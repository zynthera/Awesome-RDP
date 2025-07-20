import os
import pytest
from xploit_ninja_official import connect_rdp

def test_connect_rdp_success(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test_jwt_secret")
    monkeypatch.setenv("ENCRYPTION_KEY", "test_encryption_key")
    # Generate valid JWT & TOTP
    import jwt, pyotp
    jwt_token = jwt.encode({"user": "test"}, os.getenv("JWT_SECRET"), algorithm="HS256")
    totp = pyotp.TOTP(os.getenv("ENCRYPTION_KEY"))
    totp_code = totp.now()
    # Use localhost for test
    result = connect_rdp("127.0.0.1", "8000", os.getenv("ENCRYPTION_KEY"), totp_code, jwt_token)
    assert result is True

def test_connect_rdp_invalid_ip():
    result = connect_rdp("999.999.999.999", "8000", "key", "123456", "token")
    assert result is False

def test_connect_rdp_invalid_port():
    result = connect_rdp("127.0.0.1", "99999", "key", "123456", "token")
    assert result is False