import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "OmniSecurity AI"
    APP_VERSION: str = "1.0.0"
    PORT: int = 8787
    HOST: str = "0.0.0.0"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = f"sqlite+aiosqlite:///{os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security_agent.db').replace(chr(92), '/')}"

    # Public URL
    PUBLIC_APP_URL: str = "http://127.0.0.1:8787"
    
    # Offering & Pricing in AED
    OFFERING_NAME: str = "24/7 Corporate Cyber Hygiene, SSL & Web Vulnerability Hardening Shield"
    OFFERING_DESCRIPTION: str = "Turnkey remediation for missing HTTP security headers (HSTS, CSP, X-Frame), SSL cipher hardening, public admin surface lockdown, and server information leaks."
    DEFAULT_DEAL_VALUE: float = 1850.0 # AED 1,850 (Essential Hardening)
    ENTERPRISE_DEAL_VALUE: float = 3850.0 # AED 3,850 (Full Corporate Shield)
    
    # Operator
    OPERATOR_NAME: str = "Athul raj"
    OPERATOR_TITLE: str = "Cybersecurity Infrastructure & Threat Defense Specialist"
    OPERATOR_EMAIL: str = "athulaisolutions@gmail.com"
    OPERATOR_TELEGRAM: str = "@dreamer_comrade"
    OPERATOR_WHATSAPP: str = "+971547400174"
    
    # SMTP / Brevo Outbound
    SMTP_ENABLED: bool = True
    SMTP_HOST: str = "smtp-relay.brevo.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = "athulaisolutions@gmail.com"
    SMTP_PASSWORD: str = "" # Injected from env or fallback
    FROM_EMAIL: str = "athulaisolutions@gmail.com"
    FROM_NAME: str = "Athul - Cyber Defense Solutions"
    
    # Operational Limits & Timing
    MAX_DAILY_AUDITS: int = 50
    AUDIT_FOLLOWUP_DAYS: int = 3
    AGENT_ENABLED: bool = True
    SIMULATION_MODE: bool = False
    HEALTH_PING_INTERVAL_MINUTES: int = 5
    
    # Telegram Notifications
    NOTIFY_TELEGRAM: bool = True
    TELEGRAM_BOT_TOKEN: str = "8706330311:AAFpYrvU3kmVVQOHEkYvDHS5WwGQmA_t8yU"
    TELEGRAM_CHAT_ID: str = "@dreamer_comrade"
    
    # Heartbeat
    HEARTBEAT_ENABLED: bool = True
    HEARTBEAT_PING_URL: str = "https://hc-ping.com/demo-security-uuid"
    
    class Config:
        env_file = ".env"
        extra = "allow"

VALID_DEFAULT_BREVO_KEY = os.environ.get("SMTP_PASSWORD", "")

settings = Settings()
if not settings.SMTP_PASSWORD:
    settings.SMTP_PASSWORD = VALID_DEFAULT_BREVO_KEY

if os.environ.get("RENDER_EXTERNAL_URL"):
    settings.PUBLIC_APP_URL = os.environ.get("RENDER_EXTERNAL_URL").rstrip("/")
