from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), nullable=False)  # ADMIN | OFFICER | AUDITOR


class Screening(Base):
    __tablename__ = "screenings"
    id = Column(String(20), primary_key=True)
    doc_type = Column(String(16), nullable=False)
    doc_number_masked = Column(String(32))
    file_path = Column(String(255), nullable=False)  # encrypted copy on disk
    doc_sha256 = Column(String(64), nullable=False)
    status = Column(String(24), nullable=False)
    risk_score = Column(Integer)
    risk_level = Column(String(10))
    reason_codes = Column(Text, default="")
    issuer_status = Column(String(32))
    recommended_action = Column(String(24))
    decision = Column(String(24))
    result_json = Column(Text, nullable=False)
    created_by = Column(String(64))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    id = Column(Integer, primary_key=True)
    event = Column(String(40), nullable=False)
    subject = Column(String(20), index=True)
    payload = Column(Text, nullable=False)       # canonical JSON, no personal data
    entry_hash = Column(String(64), nullable=False)
    block_index = Column(Integer, index=True)    # NULL until sealed into a block
    created_at = Column(DateTime, default=datetime.utcnow)


class LedgerBlock(Base):
    __tablename__ = "ledger_blocks"
    block_index = Column(Integer, primary_key=True)  # PK stops two replicas sealing the same index
    prev_hash = Column(String(64), nullable=False)
    merkle_root = Column(String(64), nullable=False)
    block_hash = Column(String(64), nullable=False)
    signature = Column(String(64), nullable=False)
    sealed_at = Column(DateTime, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    screening_id = Column(String(20), index=True)
    severity = Column(String(10), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(12), default="OPEN")
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
