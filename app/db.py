import json
import os
from urllib.parse import quote, urlsplit, urlunsplit, parse_qsl, urlencode
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .settings import settings

class Base(DeclarativeBase):
    pass

def cloud_database_url():
    raw = os.getenv("VCAP_SERVICES")
    if not raw:
        return None
    try:
        services = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Invalid VCAP_SERVICES") from exc
    for group in services.values():
        if not isinstance(group, list):
            continue
        for service in group:
            credentials = service.get("credentials") or {}
            if not isinstance(credentials, dict):
                continue
            label = str(service.get("label", "")).lower()
            uri = credentials.get("uri") or credentials.get("url")
            if uri and str(uri).startswith(("postgres://", "postgresql://", "postgresql+psycopg://")):
                return secure_url(uri)
            if not any(s in label for s in ("postgres", "psql", "aws-rds")):
                continue
            host = credentials.get("host") or credentials.get("hostname")
            username = credentials.get("username") or credentials.get("user")
            password = credentials.get("password")
            name = credentials.get("dbname") or credentials.get("name") or credentials.get("database")
            if host and username and password is not None and name:
                return secure_url("postgresql://%s:%s@%s:%s/%s" % (
                    quote(str(username), safe=""), quote(str(password), safe=""),
                    host, credentials.get("port", 5432), quote(str(name), safe="")))
    return None

def secure_url(url):
    parsed = urlsplit(url.replace("postgres://", "postgresql://", 1))
    params = dict(parse_qsl(parsed.query))
    params.setdefault("sslmode", "require")
    return urlunsplit(("postgresql+psycopg", parsed.netloc, parsed.path, urlencode(params), parsed.fragment))

def resolve_database_url():
    if settings.demo_mode:
        if settings.dev_auth:
            raise RuntimeError('Development authentication forbidden in demo mode')
        if not (os.getenv('VCAP_APPLICATION') or settings.cloud_foundry):
            raise RuntimeError('Demo mode requires Cloud Foundry')
        return 'sqlite:////tmp/vulntrack-demo.db'
    if os.getenv("VCAP_APPLICATION") or settings.cloud_foundry:
        if settings.dev_auth:
            raise RuntimeError("Development authentication forbidden on Cloud Foundry")
        url = cloud_database_url()
        if not url:
            raise RuntimeError("Cloud Foundry requires a bound PostgreSQL service")
        return url
    return settings.database_url

url = resolve_database_url()
engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {}, pool_pre_ping=True)
if url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(conn, record):
        conn.execute("PRAGMA foreign_keys=ON")
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

def session():
    with SessionLocal() as db:
        yield db
