import asyncio
import datetime
import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select, and_

from config import settings
from database import AsyncSessionLocal
from models import Lead
from services.prospector import prospector
from services.outreach import security_outreach
from services.notifier import notifier

scheduler = AsyncIOScheduler()

async def job_security_scanning():
    """Background job that discovers and scans domains."""
    if not settings.AGENT_ENABLED:
        return
    try:
        await prospector.run_discovery_and_audit_cycle()
    except Exception as e:
        print(f"[Scheduler Scanner Error] {e}")

async def job_security_outreach():
    """Background job that dispatches pending security alerts."""
    if not settings.AGENT_ENABLED:
        return
    try:
        async with AsyncSessionLocal() as session:
            # Pick audited leads that have not been contacted yet
            leads = (await session.execute(
                select(Lead).where(Lead.status == "AUDITED").limit(5)
            )).scalars().all()

            for lead in leads:
                await security_outreach.dispatch_audit_pitch(lead.id)
                await asyncio.sleep(2)
    except Exception as e:
        print(f"[Scheduler Outreach Error] {e}")

async def job_heartbeat():
    """Pings the external heartbeat watchdog."""
    if not settings.HEARTBEAT_ENABLED or not settings.HEARTBEAT_PING_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            await client.get(settings.HEARTBEAT_PING_URL)
    except Exception:
        pass

def start_scheduler():
    """Initializes APScheduler background routines."""
    if scheduler.running:
        return
    scheduler.add_job(job_security_scanning, "interval", hours=4, id="job_security_scanning", replace_existing=True)
    scheduler.add_job(job_security_outreach, "interval", hours=1, id="job_security_outreach", replace_existing=True)
    scheduler.add_job(job_heartbeat, "interval", minutes=settings.HEALTH_PING_INTERVAL_MINUTES, id="job_heartbeat", replace_existing=True)
    scheduler.start()
    print("[Scheduler] OmniSecurity AI background loops activated.")
