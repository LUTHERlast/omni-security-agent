import os
import json
import datetime
from fastapi import FastAPI, Depends, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from config import settings
from database import get_db, init_db
from models import Lead, SecurityAudit, SecurityEvent, EmailLog
from services.security_scanner import security_scanner
from services.prospector import prospector
from services.scheduler import start_scheduler
from services.notifier import notifier

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)

BASE_DIR = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.on_event("startup")
async def startup_event():
    await init_db()
    start_scheduler()

@app.get("/api/ping")
@app.get("/api/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check endpoint for Render and external watchdog."""
    total_audits = (await db.execute(select(func.count(SecurityAudit.id)))).scalar() or 0
    total_leads = (await db.execute(select(func.count(Lead.id)))).scalar() or 0
    return {
        "status": "HEALTHY",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "port": settings.PORT,
        "database": "CONNECTED",
        "total_audits": total_audits,
        "total_leads": total_leads,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

@app.get("/", response_class=HTMLResponse)
async def dashboard_view(request: Request, db: AsyncSession = Depends(get_db)):
    """Executive Dashboard View."""
    total_audits = (await db.execute(select(func.count(SecurityAudit.id)))).scalar() or 0
    critical_risks = (await db.execute(select(func.count(SecurityAudit.id)).where(SecurityAudit.risk_level == "CRITICAL"))).scalar() or 0
    total_leads = (await db.execute(select(func.count(Lead.id)))).scalar() or 0
    paid_count = (await db.execute(select(func.count(Lead.id)).where(Lead.status == "PAID"))).scalar() or 0
    actual_revenue = (await db.execute(select(func.sum(Lead.deal_value)).where(Lead.status == "PAID"))).scalar() or 0.0

    audits = (await db.execute(select(SecurityAudit).order_by(desc(SecurityAudit.id)).limit(25))).scalars().all()
    events = (await db.execute(select(SecurityEvent).order_by(desc(SecurityEvent.id)).limit(20))).scalars().all()

    pipeline_value = total_leads * settings.DEFAULT_DEAL_VALUE

    stats = {
        "pipeline_value": pipeline_value,
        "total_audits": total_audits,
        "critical_risks": critical_risks,
        "total_leads": total_leads,
        "actual_revenue": actual_revenue,
        "paid_count": paid_count
    }

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "settings": settings,
            "stats": stats,
            "audits": audits,
            "events": events
        }
    )

@app.get("/security-audit/{domain}", response_class=HTMLResponse)
async def security_audit_scorecard(domain: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Public Interactive Cyber Hygiene Scorecard."""
    clean_domain = security_scanner.clean_domain(domain)
    audit = (await db.execute(select(SecurityAudit).where(SecurityAudit.domain == clean_domain))).scalar_one_or_none()

    if not audit:
        # Run real-time scan if not already cached
        res = await security_scanner.scan_domain(clean_domain)
        audit = SecurityAudit(
            domain=clean_domain,
            company_name=res["company_name"],
            overall_score=res["overall_score"],
            security_grade=res["security_grade"],
            risk_level=res["risk_level"],
            ssl_status=res["ssl_info"].get("status", "VALID"),
            ssl_days_left=res["ssl_info"].get("days_left", 0),
            ssl_issuer=res["ssl_info"].get("issuer"),
            tls_version=res["ssl_info"].get("tls_version"),
            hsts_status="PASS" if res["headers_info"]["hsts"]["present"] else "MISSING",
            csp_status="PASS" if res["headers_info"]["csp"]["present"] else "MISSING",
            x_frame_status="PASS" if res["headers_info"]["x_frame_options"]["present"] else "MISSING",
            x_content_type_status="PASS" if res["headers_info"]["x_content_type"]["present"] else "MISSING",
            referrer_policy_status="PASS" if res["headers_info"]["referrer_policy"]["present"] else "MISSING",
            server_signature=res["headers_info"].get("server_signature"),
            exposed_admin_found=len(res["exposed_endpoints"]) > 0,
            exposed_endpoints_json=json.dumps(res["exposed_endpoints"]),
            issues_json=json.dumps(res["issues"]),
            remediation_blueprint_json=json.dumps(res["remediation_blueprint"]),
            audit_token=res["audit_token"]
        )
        db.add(audit)
        await db.commit()
        await db.refresh(audit)

    issues = json.loads(audit.issues_json) if audit.issues_json else []
    blueprint = json.loads(audit.remediation_blueprint_json) if audit.remediation_blueprint_json else []

    return templates.TemplateResponse(
        request=request,
        name="security_scorecard.html",
        context={
            "request": request,
            "settings": settings,
            "audit": audit,
            "issues": issues,
            "blueprint": blueprint
        }
    )

@app.get("/security-checkout/{domain}", response_class=HTMLResponse)
async def checkout_view(domain: str, request: Request):
    """Checkout and settlement page."""
    clean_domain = security_scanner.clean_domain(domain)
    return templates.TemplateResponse(
        request=request,
        name="checkout.html",
        context={
            "request": request,
            "settings": settings,
            "domain": clean_domain
        }
    )

@app.post("/api/audit-now")
async def api_audit_now(request: Request, db: AsyncSession = Depends(get_db)):
    """API for real-time live domain scanning."""
    data = await request.json()
    raw_domain = data.get("domain", "")
    if not raw_domain:
        return JSONResponse({"error": "Domain is required"}, status_code=400)

    clean_domain = security_scanner.clean_domain(raw_domain)
    res = await security_scanner.scan_domain(clean_domain)

    # Persist or update
    audit = (await db.execute(select(SecurityAudit).where(SecurityAudit.domain == clean_domain))).scalar_one_or_none()
    if not audit:
        audit = SecurityAudit(domain=clean_domain)
        db.add(audit)

    audit.company_name = res["company_name"]
    audit.overall_score = res["overall_score"]
    audit.security_grade = res["security_grade"]
    audit.risk_level = res["risk_level"]
    audit.ssl_status = res["ssl_info"].get("status", "VALID")
    audit.ssl_days_left = res["ssl_info"].get("days_left", 0)
    audit.ssl_issuer = res["ssl_info"].get("issuer")
    audit.tls_version = res["ssl_info"].get("tls_version")
    audit.hsts_status = "PASS" if res["headers_info"]["hsts"]["present"] else "MISSING"
    audit.csp_status = "PASS" if res["headers_info"]["csp"]["present"] else "MISSING"
    audit.x_frame_status = "PASS" if res["headers_info"]["x_frame_options"]["present"] else "MISSING"
    audit.x_content_type_status = "PASS" if res["headers_info"]["x_content_type"]["present"] else "MISSING"
    audit.referrer_policy_status = "PASS" if res["headers_info"]["referrer_policy"]["present"] else "MISSING"
    audit.server_signature = res["headers_info"].get("server_signature")
    audit.exposed_admin_found = len(res["exposed_endpoints"]) > 0
    audit.exposed_endpoints_json = json.dumps(res["exposed_endpoints"])
    audit.issues_json = json.dumps(res["issues"])
    audit.remediation_blueprint_json = json.dumps(res["remediation_blueprint"])
    audit.audit_token = res["audit_token"]

    await db.commit()
    return JSONResponse(res)

@app.post("/api/actions/prospect-now")
async def api_prospect_now():
    """Manual trigger for batch discovery & audit."""
    res = await prospector.run_discovery_and_audit_cycle()
    return JSONResponse(res)

@app.post("/api/checkout/complete")
async def api_checkout_complete(request: Request, db: AsyncSession = Depends(get_db)):
    """Receives settlement orders and alerts operator."""
    data = await request.json()
    domain = security_scanner.clean_domain(data.get("domain", ""))
    client_name = data.get("name", "Corporate Client")
    client_email = data.get("email", "")
    client_phone = data.get("phone", "")
    package = data.get("package", "essential")
    amount = float(data.get("amount", settings.DEFAULT_DEAL_VALUE))

    # Link lead
    lead = (await db.execute(select(Lead).where(Lead.domain == domain))).scalar_one_or_none()
    if not lead:
        lead = Lead(domain=domain, company_name=domain)
        db.add(lead)

    lead.status = "PAID"
    lead.deal_value = amount
    lead.contact_name = client_name
    lead.contact_email = client_email
    lead.phone = client_phone
    lead.paid_at = datetime.datetime.utcnow()

    await db.commit()

    order_id = f"CYBER-{domain.replace('.', '').upper()[:6]}"

    await notifier.log_event(
        "SUCCESS",
        "ORDER",
        f"💰 NEW CYBER DEFENSE ORDER: {domain} confirmed for AED {amount:,.2f}!",
        f"Client: {client_name} ({client_email} | {client_phone}) | Package: {package} | Ref: {order_id}"
    )

    return JSONResponse({"status": "SUCCESS", "order_id": order_id, "amount": amount})

@app.get("/api/stats")
async def api_stats(db: AsyncSession = Depends(get_db)):
    """Stats endpoint formatted for OmniFleet Master aggregation."""
    total_audits = (await db.execute(select(func.count(SecurityAudit.id)))).scalar() or 0
    total_leads = (await db.execute(select(func.count(Lead.id)))).scalar() or 0
    paid_count = (await db.execute(select(func.count(Lead.id)).where(Lead.status == "PAID"))).scalar() or 0
    actual_revenue = (await db.execute(select(func.sum(Lead.deal_value)).where(Lead.status == "PAID"))).scalar() or 0.0
    critical_risks = (await db.execute(select(func.count(SecurityAudit.id)).where(SecurityAudit.risk_level == "CRITICAL"))).scalar() or 0

    pipeline_value = total_leads * settings.DEFAULT_DEAL_VALUE

    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "currency": "AED",
        "currency_symbol": "AED",
        "total_leads": total_leads,
        "pipeline_value": pipeline_value,
        "active_leads_count": total_leads - paid_count,
        "actual_revenue": actual_revenue,
        "contacted_count": (await db.execute(select(func.count(Lead.id)).where(Lead.status == "CONTACTED"))).scalar() or 0,
        "hot_leads_count": (await db.execute(select(func.count(Lead.id)).where(Lead.status == "REPLIED_INTERESTED"))).scalar() or 0,
        "paid_count": paid_count,
        "won_count": paid_count,
        "total_audits": total_audits,
        "critical_risks": critical_risks,
        "agent_enabled": settings.AGENT_ENABLED,
        "simulation_mode": settings.SIMULATION_MODE,
        "heartbeat_status": "OK" if settings.HEARTBEAT_ENABLED else "OFF"
    }

@app.get("/api/events")
async def api_events(db: AsyncSession = Depends(get_db)):
    events = (await db.execute(select(SecurityEvent).order_by(desc(SecurityEvent.id)).limit(25))).scalars().all()
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "level": e.level,
            "category": e.category,
            "message": e.message,
            "details": e.details
        }
        for e in events
    ]
