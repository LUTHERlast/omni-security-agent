import ssl
import smtplib
import asyncio
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from config import settings
from database import AsyncSessionLocal
from models import Lead, EmailLog, SecurityEvent, SecurityAudit
from services.notifier import notifier

class SecurityOutreachEngine:
    """Dispatches cyber hygiene alerts and scorecard proposals."""

    def __init__(self):
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_pass = settings.SMTP_PASSWORD
        self.from_email = settings.FROM_EMAIL
        self.from_name = settings.FROM_NAME

    def generate_pitch(self, lead: Lead, audit: SecurityAudit) -> Tuple[str, str]:
        """Generates hyper-personalized cyber hygiene vulnerability alert."""
        domain = lead.domain
        company = lead.company_name or domain
        score = audit.overall_score
        grade = audit.security_grade
        scorecard_url = f"{settings.PUBLIC_APP_URL}/security-audit/{domain}"

        subject = f"Urgent Security Diagnostic: {domain} scored {grade} ({score}/100) on Public Header & SSL Audit"

        body = f"""Dear {company} Technology & Executive Team,

Our autonomous security diagnostic platform performed a routine, non-intrusive public cyber hygiene audit on {domain}.

Audit Findings for {domain}:
• Overall Security Grade: {grade} ({score} / 100)
• Risk Classification: {audit.risk_level}
• Critical Vulnerabilities Detected: {audit.hsts_status} HSTS Policy, {audit.csp_status} Content Security Policy

Why This Matters:
Without strict HSTS and modern security headers, your corporate website is susceptible to SSL stripping, clickjacking, and man-in-the-middle exploits that can compromise user trust and corporate compliance.

View Your Complete Interactive Cyber Hygiene Scorecard & Remediation Blueprint:
👉 {scorecard_url}

Turnkey Resolution:
We provide an immediate, zero-downtime hardening package for UAE B2B companies (AED {settings.DEFAULT_DEAL_VALUE:,.2f}) that resolves all header vulnerabilities and secures your domain within 24 hours.

Would you like us to implement this remediation for {domain} this week?

Warm regards,

{settings.OPERATOR_NAME}
{settings.OPERATOR_TITLE}
Direct: {settings.OPERATOR_EMAIL}
WhatsApp / Support: {settings.OPERATOR_WHATSAPP}
Platform: {settings.PUBLIC_APP_URL}
"""
        return subject, body

    async def send_email(self, to_email: str, subject: str, body: str) -> bool:
        """Sends email via authenticated Brevo SMTP relay."""
        if settings.SIMULATION_MODE or not settings.SMTP_ENABLED or not self.smtp_pass:
            print(f"[Outreach SIMULATION] Would send to {to_email}: {subject}")
            return True

        def _sync_send():
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = to_email
            msg.attach(MIMEText(body, "plain"))

            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=12.0) as server:
                server.starttls(context=context)
                server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.from_email, [to_email], msg.as_string())
            return True

        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, _sync_send)
        except Exception as e:
            print(f"[Outreach SMTP Error] {e}")
            await notifier.log_event("ERROR", "OUTREACH", f"Failed to send security pitch to {to_email}: {e}")
            return False

    async def dispatch_audit_pitch(self, lead_id: int) -> bool:
        """Dispatches security alert and records outcome in database."""
        async with AsyncSessionLocal() as session:
            lead = await session.get(Lead, lead_id)
            if not lead or not lead.contact_email:
                return False

            audit = await session.get(SecurityAudit, lead.audit_id) if lead.audit_id else None
            if not audit:
                return False

            subject, body = self.generate_pitch(lead, audit)
            success = await self.send_email(lead.contact_email, subject, body)

            if success:
                lead.emails_sent_count += 1
                lead.last_contacted_at = datetime.datetime.utcnow()
                lead.status = "CONTACTED"

                log = EmailLog(
                    lead_id=lead.id,
                    recipient=lead.contact_email,
                    subject=subject,
                    body_snippet=body[:250],
                    scorecard_url=f"{settings.PUBLIC_APP_URL}/security-audit/{lead.domain}",
                    status="SENT"
                )
                session.add(log)
                await session.commit()

                await notifier.log_event(
                    "SUCCESS",
                    "OUTREACH",
                    f"Dispatched Cyber Hygiene Alert to {lead.company_name} ({lead.contact_email})",
                    f"Score: {audit.overall_score}/100 ({audit.security_grade}) | Scorecard: {settings.PUBLIC_APP_URL}/security-audit/{lead.domain}"
                )
                return True
            return False

security_outreach = SecurityOutreachEngine()
