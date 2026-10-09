import hashlib
import hmac
import os
from datetime import datetime, timedelta

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.database import User, get_db

_ITERATIONS = 260_000
_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), _ITERATIONS)
    return hmac.compare_digest(digest.hex(), digest_hex)


def make_token(user: User) -> str:
    claims = {"sub": user.username, "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_TTL_MIN)}
    return jwt.encode(claims, settings.JWT_SECRET, algorithm="HS256")


def current_user(token: str = Depends(_oauth2), db: Session = Depends(get_db)) -> User:
    try:
        claims = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = db.query(User).filter(User.username == claims["sub"]).first()
    if not user:
        raise HTTPException(401, "Account no longer exists")
    return user


def require(*roles: str):
    """Reads the role from the database on every request, so role changes apply immediately."""

    def checker(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Your role cannot perform this action")
        return user

    return checker
