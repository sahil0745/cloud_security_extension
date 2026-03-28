# Database Schema (SQLAlchemy example for PostgreSQL)
from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class ConfigurationBaseline(Base):
    __tablename__ = 'configuration_baselines'
    id = Column(Integer, primary_key=True)
    provider = Column(String) # AWS, Azure, GCP
    resource_id = Column(String, index=True)
    resource_type = Column(String)
    safe_configuration = Column(JSON) # Encrypted JSON of safe state
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

class SecurityAlert(Base):
    __tablename__ = 'security_alerts'
    id = Column(Integer, primary_key=True)
    vulnerability_type = Column(String)
    resource_id = Column(String)
    severity = Column(String)
    risk_score = Column(Float)
    status = Column(String) # Open, Remediated, Pending Approval
    detected_at = Column(DateTime)
    remediated_at = Column(DateTime, nullable=True)

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(String)
    action = Column(String)
    resource_id = Column(String)
    timestamp = Column(DateTime)
    ip_address = Column(String)
    status = Column(String)
