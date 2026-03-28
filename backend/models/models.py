from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database.db import Base
from services.encryption import EncryptedJSONType, EncryptedTextType

class Baseline(Base):
    __tablename__ = "baselines"

    id = Column(Integer, primary_key=True, index=True)
    platform = Column(String, index=True)
    account_id = Column(String, index=True)
    configuration = Column(JSON)  # Plain JSON — no encryption for config snapshots
    version = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ConfigHistory(Base):
    __tablename__ = "config_history"

    id = Column(Integer, primary_key=True, index=True)
    baseline_id = Column(Integer, ForeignKey("baselines.id"))
    platform = Column(String)
    configuration = Column(JSON)  # Plain JSON — eliminates encryption key mismatch
    drift_detected = Column(JSON, nullable=True)  # Plain JSON for drift details
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="USER") # USER or ADMIN
    is_active = Column(Integer, default=1)
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    risk_history = relationship("RiskHistory", back_populates="user", cascade="all, delete-orphan")
    logs = relationship("Logs", back_populates="user", cascade="all, delete-orphan")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String)
    resource = Column(EncryptedTextType)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String)
    user = relationship("User", back_populates="audit_logs")

class RiskHistory(Base):
    __tablename__ = "risk_history"
    id = Column(Integer, primary_key=True, index=True)
    score = Column(Integer)
    vulnerabilities_count = Column(Integer)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="risk_history")

class Logs(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String) # anomaly, remediation, alert
    description = Column(EncryptedTextType)
    resource_id = Column(String, nullable=True)
    previous_hash = Column(String(128), nullable=True)
    log_hash = Column(String(128), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="logs")

class ApprovalRequest(Base):
    __tablename__ = "approval_requests"
    id = Column(Integer, primary_key=True, index=True)
    action_id = Column(String, unique=True, index=True)
    action_type = Column(String)
    target_resource = Column(String)
    otp_code = Column(EncryptedTextType)
    expires_at = Column(DateTime)
    status = Column(String, default="PENDING") # PENDING, APPROVED, REJECTED

