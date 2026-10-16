from dataclasses import dataclass
from fastapi import Depends, Header, HTTPException
import jwt
from jwt import PyJWKClient
from .settings import settings

@dataclass
class Principal:
    subject: str
    admin: bool = False

def principal(authorization: str | None = Header(default=None)) -> Principal:
    if settings.dev_auth and not settings.oidc_issuer:
        return Principal("local-dev", admin=True)
    if not settings.oidc_issuer or not settings.oidc_jwks_url:
        raise HTTPException(503, "OIDC provider not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization.removeprefix("Bearer ")
    try:
        signing_key = PyJWKClient(settings.oidc_jwks_url).get_signing_key_from_jwt(token)
        claims = jwt.decode(token, signing_key.key, algorithms=["RS256", "ES256"], issuer=settings.oidc_issuer, audience=settings.oidc_audience, options={"require": ["sub", "exp", "iss", "aud"]})
    except (jwt.PyJWTError, ValueError, ConnectionError) as exc:
        raise HTTPException(401, "Invalid identity token") from exc
    allowed = {item.strip() for item in settings.admin_subjects.split(",") if item.strip()}
    return Principal(claims["sub"], admin=claims["sub"] in allowed or "vulntrack-admin" in claims.get("roles", []))

def admin(user: Principal = Depends(principal)) -> Principal:
    if not user.admin: raise HTTPException(403, "Administrator required")
    return user
