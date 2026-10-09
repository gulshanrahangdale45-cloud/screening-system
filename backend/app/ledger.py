"""
Permissioned, hash-linked ledger (blockchain pattern).

- Each event becomes an entry whose hash covers its canonical payload.
- Entries are sealed into blocks. A block stores the Merkle root of its entries,
  the hash of the previous block, and an HMAC signature made with a server key.
- verify_ledger() recomputes all of it, so any edit, deletion, insertion or
  reordering of past records is detected and the broken block is reported.

This is a tamper-evident ledger operated by one organisation, not a public
blockchain. Payloads never contain personal data, only hashes and decision codes.
"""

import hashlib
import hmac
import json
from datetime import datetime

from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.database import LedgerBlock, LedgerEntry

GENESIS = "0" * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _merkle(hashes: list[str]) -> str:
    if not hashes:
        return GENESIS
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _entry_hash(event: str, subject: str, payload: str) -> str:
    return _sha(f"{event}|{subject}|{payload}")


def _header_hash(index: int, prev: str, root: str, ts: str) -> str:
    return _sha(f"{index}|{prev}|{root}|{ts}")


def _sign(block_hash: str) -> str:
    return hmac.new(settings.LEDGER_KEY.encode(), block_hash.encode(), hashlib.sha256).hexdigest()


def append_event(db, event: str, subject: str, payload: dict) -> str:
    body = _canon(payload)
    entry_hash = _entry_hash(event, subject, body)
    db.add(LedgerEntry(event=event, subject=subject, payload=body, entry_hash=entry_hash))
    db.commit()
    pending = db.query(func.count(LedgerEntry.id)).filter(LedgerEntry.block_index.is_(None)).scalar()
    if pending >= settings.LEDGER_SEAL_EVERY:
        seal(db)
    return entry_hash


def seal(db):
    if db.bind.dialect.name == "postgresql":
        # Serialises sealing across API replicas for the duration of the transaction
        db.execute(text("SELECT pg_advisory_xact_lock(4242)"))

    pending = (
        db.query(LedgerEntry)
        .filter(LedgerEntry.block_index.is_(None))
        .order_by(LedgerEntry.id)
        .all()
    )
    if not pending:
        db.rollback()
        return None

    last = db.query(LedgerBlock).order_by(LedgerBlock.block_index.desc()).first()
    index = last.block_index + 1 if last else 0
    prev = last.block_hash if last else GENESIS
    root = _merkle([e.entry_hash for e in pending])
    ts = datetime.utcnow()
    block_hash = _header_hash(index, prev, root, ts.isoformat())

    db.add(LedgerBlock(block_index=index, prev_hash=prev, merkle_root=root,
                       block_hash=block_hash, signature=_sign(block_hash), sealed_at=ts))
    for e in pending:
        e.block_index = index
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # another replica sealed this index first; a later call retries
        return None
    return {"block_index": index, "block_hash": block_hash, "entries": len(pending),
            "message": f"Sealed block {index} with {len(pending)} entries"}


def verify_ledger(db) -> dict:
    def fail(index: int, reason: str) -> dict:
        return {"valid": False, "broken_at_block": index,
                "message": f"Ledger FAILED at block {index}: {reason}"}

    blocks = db.query(LedgerBlock).order_by(LedgerBlock.block_index).all()
    prev, checked = GENESIS, 0
    for b in blocks:
        if b.prev_hash != prev:
            return fail(b.block_index, "link to the previous block is broken")
        entries = (
            db.query(LedgerEntry)
            .filter(LedgerEntry.block_index == b.block_index)
            .order_by(LedgerEntry.id)
            .all()
        )
        if any(_entry_hash(e.event, e.subject, e.payload) != e.entry_hash for e in entries):
            return fail(b.block_index, "an entry was altered")
        if _merkle([e.entry_hash for e in entries]) != b.merkle_root:
            return fail(b.block_index, "entries were added, removed or reordered")
        if _header_hash(b.block_index, b.prev_hash, b.merkle_root, b.sealed_at.isoformat()) != b.block_hash:
            return fail(b.block_index, "block header was altered")
        if not hmac.compare_digest(_sign(b.block_hash), b.signature):
            return fail(b.block_index, "signature is invalid")
        prev = b.block_hash
        checked += len(entries)

    pending = db.query(func.count(LedgerEntry.id)).filter(LedgerEntry.block_index.is_(None)).scalar()
    return {"valid": True, "blocks": len(blocks), "entries_checked": checked,
            "pending_entries": pending, "message": "Ledger intact"}
