import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, Boolean
from database import Base

class SecurityAudit(Base):
    __tablename__ = "security_audits"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    company_name = Column(String(255), nullable=True)
    overall_score = Column(Integer, default=0) # 0 to 100
    security_grade = Column(String(10), default="F") # A+, A, B, C, D, F
    risk_level = Column(String(50), default="CRITICAL") # OPTIMAL, LOW, MODERATE, HIGH, CRITICAL
    
    # SSL/TLS Diagnostics
    ssl_status = Column(String(50), default="UNKNOWN")
    ssl_days_left = Column(Integer, default=0)
    ssl_issuer = Column(String(255), nullable=True)
    tls_version = Column(String(50), nullable=True)
    
    # HTTP Security Headers
    hsts_status = Column(String(50), default="MISSING")
    csp_status = Column(String(50), default="MISSING")
    x_frame_status = Column(String(50), default="MISSING")
    x_content_type_status = Column(String(50), default="MISSING")
    referrer_policy_status = Column(String(50), default="MISSING")
    
    # Information Disclosure & Exposure
    server_signature = Column(String(255), nullable=True) # e.g. "Apache/2.4.41 (Ubuntu)"
    tech_stack = Column(String(255), nullable=True) # e.g. "PHP/7.4.33, WordPress"
    exposed_admin_found = Column(Boolean, default=False)
    exposed_endpoints_json = Column(Text, default="[]") # JSON list of exposed paths
    
    # Issues & Blueprint
    issues_json = Column(Text, default="[]") # Detailed vulnerabilities breakdown
    remediation_blueprint_json = Column(Text, default="[]") # Step-by-step fix guide
    audit_token = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Lead(Base):
    __tablename__ = "leads"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    company_name = Column(String(255), nullable=True)
    industry = Column(String(255), nullable=True)
    location = Column(String(255), default="Dubai, UAE")
    contact_name = Column(String(255), nullable=True)
    contact_email = Column(String(255), nullable=True)
    contact_role = Column(String(255), default="CTO / IT Director / Managing Director")
    phone = Column(String(100), nullable=True)
    
    # Pipeline & Deal
    status = Column(String(50), default="DISCOVERED") # DISCOVERED, AUDITED, CONTACTED, REPLIED_INTERESTED, WON, PAID
    deal_value = Column(Float, default=1850.0) # in AED
    audit_id = Column(Integer, ForeignKey("security_audits.id"), nullable=True)
    
    # Outreach Tracker
    emails_sent_count = Column(Integer, default=0)
    last_contacted_at = Column(DateTime, nullable=True)
    next_followup_at = Column(DateTime, nullable=True)
    
    # Reply info
    reply_sentiment = Column(String(50), nullable=True)
    last_reply_text = Column(Text, nullable=True)
    last_reply_at = Column(DateTime, nullable=True)
    
    paid_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    level = Column(String(20), default="INFO") # INFO, SUCCESS, WARNING, CRITICAL, ERROR
    category = Column(String(50), default="SCANNER") # SCANNER, OUTREACH, WEBHOOK, SYSTEM
    message = Column(String(500), nullable=False)
    details = Column(Text, nullable=True)

class EmailLog(Base):
    __tablename__ = "email_logs"

    id = Column(Integer, primary_key=True, index=True)
    lead_id = Column(Integer, ForeignKey("leads.id"), nullable=True)
    recipient = Column(String(255), nullable=False)
    subject = Column(String(500), nullable=False)
    body_snippet = Column(Text, nullable=True)
    scorecard_url = Column(String(500), nullable=True)
    status = Column(String(50), default="SENT")
    sent_at = Column(DateTime, default=datetime.datetime.utcnow)
