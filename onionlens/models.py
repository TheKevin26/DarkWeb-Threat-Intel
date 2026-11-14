"""SQLAlchemy ORM models."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


document_indicators = Table(
    "document_indicators",
    Base.metadata,
    Column("document_id", ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True),
    Column("indicator_id", ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True),
)


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    kind: Mapped[str] = mapped_column(String(30))  # tor | api | telegram | clearnet | demo
    url: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    last_status: Mapped[str] = mapped_column(String(20), default="unknown")  # up | down | unknown

    documents: Mapped[list[Document]] = relationship(back_populates="source")
    checks: Mapped[list[SourceCheck]] = relationship(back_populates="source", cascade="all, delete-orphan")


class SourceCheck(Base):
    """Uptime history for a source."""

    __tablename__ = "source_checks"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ok: Mapped[bool] = mapped_column(Boolean)
    status_code: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(String(300))

    source: Mapped[Source] = relationship(back_populates="checks")


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), index=True)
    url: Mapped[str] = mapped_column(String(1000), index=True)
    title: Mapped[str | None] = mapped_column(String(500))
    author: Mapped[str | None] = mapped_column(String(200))
    text: Mapped[str] = mapped_column(Text)  # redacted, plain text
    translated_text: Mapped[str | None] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    raw_path: Mapped[str | None] = mapped_column(String(500))
    language: Mapped[str | None] = mapped_column(String(10))
    category: Mapped[str] = mapped_column(String(40), default="other", index=True)
    category_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    category_scores: Mapped[dict] = mapped_column(JSON, default=dict)
    entities: Mapped[list] = mapped_column(JSON, default=list)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    source: Mapped[Source] = relationship(back_populates="documents")
    indicators: Mapped[list[Indicator]] = relationship(secondary=document_indicators, back_populates="documents")
    alerts: Mapped[list[Alert]] = relationship(back_populates="document", cascade="all, delete-orphan")


class PageSnapshot(Base):
    """Every distinct version of a URL we have fetched - used for change detection."""

    __tablename__ = "page_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(1000), index=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    changed: Mapped[bool] = mapped_column(Boolean, default=False)


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("type", "value_hash"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(30), index=True)
    value: Mapped[str] = mapped_column(String(500))  # display value (masked when sensitive)
    value_hash: Mapped[str] = mapped_column(String(64))  # sha256 of the normalized raw value
    context: Mapped[str | None] = mapped_column(String(200))  # e.g. email domain, card BIN
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    sightings: Mapped[int] = mapped_column(Integer, default=1)

    documents: Mapped[list[Document]] = relationship(secondary=document_indicators, back_populates="indicators")


class Victim(Base):
    """A ransomware / extortion leak-site victim posting."""

    __tablename__ = "victims"
    __table_args__ = (UniqueConstraint("group_name", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(300))
    domain: Mapped[str | None] = mapped_column(String(300))
    group_name: Mapped[str] = mapped_column(String(100), index=True)
    country: Mapped[str | None] = mapped_column(String(100), index=True)
    sector: Mapped[str | None] = mapped_column(String(100), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id"))
    document_id: Mapped[int | None] = mapped_column(ForeignKey("documents.id"))


class VictimSighting(Base):
    """Which source reported a victim, and when. Lets us compare our own Tor crawl with third-party feeds."""

    __tablename__ = "victim_sightings"
    __table_args__ = (UniqueConstraint("victim_id", "source_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    victim_id: Mapped[int] = mapped_column(ForeignKey("victims.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class WatchlistItem(Base):
    __tablename__ = "watchlist"
    __table_args__ = (UniqueConstraint("kind", "value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(30))  # domain | keyword | email_domain | ip_range | bin
    value: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20), default="high")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int | None] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), index=True)
    victim_id: Mapped[int | None] = mapped_column(ForeignKey("victims.id", ondelete="CASCADE"))
    watch_kind: Mapped[str] = mapped_column(String(30))
    watch_value: Mapped[str] = mapped_column(String(300))
    matched: Mapped[str] = mapped_column(String(500))
    snippet: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="high")  # low | medium | high | critical
    status: Mapped[str] = mapped_column(String(20), default="new")  # new | acknowledged | resolved
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    document: Mapped[Document | None] = relationship(back_populates="alerts")


class WalletCheck(Base):
    """On-chain snapshot of a cryptocurrency wallet seen in dark web content (public blockchain data)."""

    __tablename__ = "wallet_checks"

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    tx_count: Mapped[int] = mapped_column(Integer, default=0)
    received_sats: Mapped[int] = mapped_column(BigInteger, default=0)
    sent_sats: Mapped[int] = mapped_column(BigInteger, default=0)
    balance_sats: Mapped[int] = mapped_column(BigInteger, default=0)
    pending_tx: Mapped[int] = mapped_column(Integer, default=0)
    last_tx_at: Mapped[datetime | None] = mapped_column(DateTime)
    new_tx: Mapped[int] = mapped_column(Integer, default=0)  # transactions since the previous check
    new_received_sats: Mapped[int] = mapped_column(BigInteger, default=0)


class DroppedItem(Base):
    """Audit trail of content dropped by the safety filter. Stores no content - only the reason."""

    __tablename__ = "dropped_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_hash: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(String(100))
    dropped_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
