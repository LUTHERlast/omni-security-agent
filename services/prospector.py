import json
import asyncio
import datetime
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import AsyncSessionLocal
from models import Lead, SecurityAudit
from services.security_scanner import security_scanner
from services.notifier import notifier

class SecurityProspector:
    """Discovers high-ticket UAE corporate domains and queues them for automated scanning."""

    def __init__(self):
        # High-value initial seed list of real UAE & B2B corporate domains
        self.target_seeds = [
            {"domain": "damacproperties.com", "company_name": "DAMAC Properties", "industry": "Luxury Real Estate", "email": "info@damacproperties.com", "phone": "97143731999"},
            {"domain": "alwasl.com", "company_name": "Wasl Properties", "industry": "Real Estate & Asset Management", "email": "info@wasl.com", "phone": "97143981111"},
            {"domain": "asterdmhealthcare.com", "company_name": "Aster DM Healthcare", "industry": "Healthcare & Clinics", "email": "customercare@asterdmhealthcare.com", "phone": "97144400500"},
            {"domain": "virtuzone.com", "company_name": "Virtuzone UAE", "industry": "Corporate Business Setup", "email": "info@virtuzone.com", "phone": "97144578200"},
            {"domain": "dubaichamber.com", "company_name": "Dubai Chamber", "industry": "Corporate Services", "email": "customercare@dubaichamber.com", "phone": "97142280000"},
            {"domain": "alhabtoor.com", "company_name": "Al Habtoor Group", "industry": "Conglomerate & Hospitality", "email": "info@habtoor.com", "phone": "97143999999"},
            {"domain": "azizi.com", "company_name": "Azizi Developments", "industry": "Property Development", "email": "info@azizidevelopments.com", "phone": "97143596666"},
            {"domain": "sobharealty.com", "company_name": "Sobha Realty", "industry": "Luxury Developments", "email": "info@sobharealty.com", "phone": "97144238064"},
            {"domain": "shurooq.gov.ae", "company_name": "Shurooq Investment", "industry": "Investment & Tourism", "email": "info@shurooq.gov.ae", "phone": "97165560777"},
            {"domain": "drjoydentalclinic.com", "company_name": "Dr. Joy Dental Clinic", "industry": "Cosmetic Dentistry & Orthodontics", "email": "enquiry@drjoydentalclinic.com", "phone": "97143285332"},
            {"domain": "montrealclinic.ae", "company_name": "Montreal Barsha Clinic", "industry": "Aesthetic & Medical Center", "email": "info@montrealclinic.ae", "phone": "971508990141"},
            {"domain": "startanybusiness.ae", "company_name": "Start Any Business UAE", "industry": "Corporate Licensing & Setup", "email": "info@startanybusiness.ae", "phone": "971585791578"},
            {"domain": "kingsmencarrental.com", "company_name": "Kingsmen Luxury Car Rental", "industry": "Exotic Vehicle Rentals", "email": "info@kingsmencarrental.com", "phone": "971522222567"},
            {"domain": "shuraa.com", "company_name": "Shuraa Business Setup", "industry": "Free Zone & Mainland Setup", "email": "info@shuraa.com", "phone": "97144081900"}
        ]

    async def run_discovery_and_audit_cycle(self) -> Dict[str, Any]:
        """Runs batch scanning on target domains and registers leads in the database."""
        audited_count = 0
        new_leads_count = 0

        async with AsyncSessionLocal() as session:
            for seed in self.target_seeds:
                domain = seed["domain"]
                
                # Check if already audited
                existing_audit = (await session.execute(select(SecurityAudit).where(SecurityAudit.domain == domain))).scalar_one_or_none()
                if existing_audit:
                    continue

                # Run live scan
                res = await security_scanner.scan_domain(domain, seed["company_name"])
                
                audit = SecurityAudit(
                    domain=domain,
                    company_name=seed["company_name"],
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
                session.add(audit)
                await session.flush()
                audited_count += 1

                # Create or link lead
                lead = Lead(
                    domain=domain,
                    company_name=seed["company_name"],
                    industry=seed["industry"],
                    contact_email=seed["email"],
                    phone=seed.get("phone") or res.get("detected_phone"),
                    status="AUDITED",
                    audit_id=audit.id,
                    deal_value=1850.0 # Standard Essential Hardening Package
                )
                session.add(lead)
                new_leads_count += 1

                await notifier.log_event(
                    "INFO" if audit.overall_score >= 80 else "WARNING",
                    "SCANNER",
                    f"Audited {domain} -> Score: {audit.overall_score}/100 ({audit.security_grade})",
                    f"Risk: {audit.risk_level} | Vulnerabilities: {len(res['issues'])}"
                )

            await session.commit()

        return {
            "status": "COMPLETED",
            "audited_count": audited_count,
            "new_leads_count": new_leads_count,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

prospector = SecurityProspector()
