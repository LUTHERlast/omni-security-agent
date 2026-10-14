import ssl
import socket
import datetime
import uuid
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import httpx

class SecurityScanner:
    """Non-intrusive public web security & SSL cyber hygiene scanner."""

    def __init__(self):
        self.common_exposed_paths = [
            "/wp-admin",
            "/admin",
            "/.env",
            "/.git/HEAD",
            "/phpmyadmin",
            "/server-status",
            "/api/docs",
            "/swagger"
        ]

    def clean_domain(self, raw: str) -> str:
        raw = raw.strip().lower()
        raw = re.sub(r"^https?://", "", raw)
        raw = raw.split("/")[0].split(":")[0]
        return raw

    def extract_whatsapp_phone(self, html: str) -> Optional[str]:
        """Extracts official WhatsApp or UAE mobile phone numbers from HTML."""
        if not html:
            return None
        try:
            # 1. Look for direct wa.me link
            wa_match = re.search(r'wa\.me/(\d{10,15})', html, re.IGNORECASE)
            if wa_match:
                return wa_match.group(1)

            # 2. Look for api.whatsapp.com link
            wa_api = re.search(r'api\.whatsapp\.com/send\?[^"\']*phone=(\d{10,15})', html, re.IGNORECASE)
            if wa_api:
                return wa_api.group(1)

            # 3. Look for UAE mobile pattern: +971 50/52/54/55/56/58 XXXXXXX
            uae_mob = re.search(r'(?:\+?971|00971|0)?\s*(5[024568]\d{7})', html)
            if uae_mob:
                return f"971{uae_mob.group(1)}"

            # 4. Look for tel: link with UAE digits
            tel_matches = re.findall(r'href=["\']tel:([^"\']+)["\']', html, re.IGNORECASE)
            for tel in tel_matches:
                clean = re.sub(r'[^\d]', '', tel)
                if clean.startswith("9715") and len(clean) == 12:
                    return clean
                if clean.startswith("05") and len(clean) == 10:
                    return f"971{clean[1:]}"
                if clean.startswith("9714") and len(clean) == 11:
                    return clean
        except Exception:
            pass
        return None

    def check_ssl(self, domain: str) -> Dict[str, Any]:
        """Inspects live SSL/TLS certificate."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        try:
            with socket.create_connection((domain, 443), timeout=4.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Expiry date parsing
                    not_after_str = cert.get("notAfter")
                    expire_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.utcnow()
                    days_left = (expire_date - now).days
                    
                    # Issuer
                    issuer = "Unknown CA"
                    for rdn in cert.get("issuer", ()):
                        for key, val in rdn:
                            if key == "organizationName":
                                issuer = val
                                break

                    return {
                        "valid": True,
                        "status": "VALID" if days_left > 14 else "EXPIRING_SOON",
                        "days_left": max(0, days_left),
                        "expire_date": expire_date.strftime("%Y-%m-%d"),
                        "issuer": issuer,
                        "tls_version": version,
                        "cipher": cipher[0] if cipher else "Unknown"
                    }
        except Exception as e:
            return {
                "valid": False,
                "status": "FAILED",
                "days_left": 0,
                "expire_date": "N/A",
                "issuer": "None",
                "tls_version": "N/A",
                "cipher": "N/A",
                "error": str(e)
            }

    async def check_http_headers_and_leaks(self, domain: str) -> Dict[str, Any]:
        """Inspects HTTP security headers, server banners, and redirects."""
        url = f"https://{domain}"
        headers_info = {
            "hsts": {"present": False, "value": None},
            "csp": {"present": False, "value": None},
            "x_frame_options": {"present": False, "value": None},
            "x_content_type": {"present": False, "value": None},
            "referrer_policy": {"present": False, "value": None},
            "server_signature": None,
            "x_powered_by": None,
            "https_enforced": False,
            "detected_phone": None
        }

        try:
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, verify=False) as client:
                res = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"})
                
                resp_headers = {k.lower(): v for k, v in res.headers.items()}
                
                # Check HSTS
                if "strict-transport-security" in resp_headers:
                    headers_info["hsts"]["present"] = True
                    headers_info["hsts"]["value"] = resp_headers["strict-transport-security"]

                # Check CSP
                if "content-security-policy" in resp_headers:
                    headers_info["csp"]["present"] = True
                    headers_info["csp"]["value"] = resp_headers["content-security-policy"][:120]

                # Check X-Frame-Options
                if "x-frame-options" in resp_headers:
                    headers_info["x_frame_options"]["present"] = True
                    headers_info["x_frame_options"]["value"] = resp_headers["x-frame-options"]

                # Check X-Content-Type-Options
                if "x-content-type-options" in resp_headers:
                    headers_info["x_content_type"]["present"] = True
                    headers_info["x_content_type"]["value"] = resp_headers["x-content-type-options"]

                # Check Referrer-Policy
                if "referrer-policy" in resp_headers:
                    headers_info["referrer_policy"]["present"] = True
                    headers_info["referrer_policy"]["value"] = resp_headers["referrer-policy"]

                # Leaked server info
                headers_info["server_signature"] = resp_headers.get("server")
                headers_info["x_powered_by"] = resp_headers.get("x-powered-by")
                
                # Check if landed on https
                headers_info["https_enforced"] = str(res.url).startswith("https://")
                
                # Extract official WhatsApp phone from webpage
                if res.text:
                    headers_info["detected_phone"] = self.extract_whatsapp_phone(res.text)

        except Exception as e:
            pass

        return headers_info

    async def check_exposed_endpoints(self, domain: str) -> List[Dict[str, Any]]:
        """Passive check for publicly accessible admin or sensitive paths."""
        exposed = []
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=False, verify=False) as client:
            for path in self.common_exposed_paths:
                target = f"https://{domain}{path}"
                try:
                    res = await client.get(target, headers={"User-Agent": "Mozilla/5.0"})
                    # Status 200 or 401/403 with specific login prompts
                    if res.status_code == 200 and len(res.text) > 50:
                        if "404" not in res.text.lower() and "not found" not in res.text.lower():
                            exposed.append({
                                "path": path,
                                "status_code": res.status_code,
                                "risk": "HIGH" if ".env" in path or ".git" in path else "MODERATE",
                                "description": f"Publicly accessible gateway at {path}"
                            })
                except Exception:
                    continue
        return exposed

    async def scan_domain(self, raw_domain: str, company_name: Optional[str] = None) -> Dict[str, Any]:
        """Executes complete automated cyber hygiene and vulnerability scan."""
        domain = self.clean_domain(raw_domain)
        if not company_name:
            company_name = domain.split(".")[0].capitalize()

        # 1. Run checks
        ssl_info = self.check_ssl(domain)
        headers_info = await self.check_http_headers_and_leaks(domain)
        exposed_endpoints = await self.check_exposed_endpoints(domain)

        # 2. Compute Security Score (Starting at 100)
        score = 100
        issues = []
        blueprint = []

        # SSL evaluation
        if not ssl_info["valid"]:
            score -= 40
            issues.append({
                "severity": "CRITICAL",
                "title": "Invalid or Missing SSL/TLS Certificate",
                "description": f"HTTPS is not properly secured ({ssl_info.get('error', 'connection refused')}). Browsers display red security warnings.",
                "penalty": 40
            })
            blueprint.append({
                "component": "SSL/TLS",
                "action": "Deploy Let's Encrypt or Cloudflare TLS 1.3 Certificate with auto-renewal."
            })
        elif ssl_info["days_left"] < 15:
            score -= 15
            issues.append({
                "severity": "HIGH",
                "title": f"SSL Certificate Expiring in {ssl_info['days_left']} Days",
                "description": "Certificate will expire imminently. Failure to renew triggers browser lockout warnings.",
                "penalty": 15
            })
            blueprint.append({
                "component": "SSL Expiry",
                "action": "Trigger emergency TLS certificate re-issue and setup automated 60-day renewal cycle."
            })

        # HSTS evaluation
        if not headers_info["hsts"]["present"]:
            score -= 20
            issues.append({
                "severity": "CRITICAL",
                "title": "Missing HSTS (Strict-Transport-Security)",
                "description": "Domain is vulnerable to Man-in-the-Middle (MITM) downgrade attacks and SSL stripping.",
                "penalty": 20
            })
            blueprint.append({
                "component": "HSTS Header",
                "action": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            })

        # CSP evaluation
        if not headers_info["csp"]["present"]:
            score -= 15
            issues.append({
                "severity": "HIGH",
                "title": "Missing Content-Security-Policy (CSP)",
                "description": "No baseline defense against Cross-Site Scripting (XSS), malicious third-party script injection, and click fraud.",
                "penalty": 15
            })
            blueprint.append({
                "component": "CSP Header",
                "action": "Configure Content-Security-Policy directive defining authorized script and media sources."
            })

        # X-Frame-Options evaluation
        if not headers_info["x_frame_options"]["present"]:
            score -= 10
            issues.append({
                "severity": "MODERATE",
                "title": "Missing X-Frame-Options (Clickjacking Risk)",
                "description": "Site can be embedded in malicious invisible iFrames on external phishing domains to hijack clicks.",
                "penalty": 10
            })
            blueprint.append({
                "component": "X-Frame-Options",
                "action": "Add: X-Frame-Options: SAMEORIGIN"
            })

        # X-Content-Type-Options
        if not headers_info["x_content_type"]["present"]:
            score -= 5
            issues.append({
                "severity": "LOW",
                "title": "Missing X-Content-Type-Options",
                "description": "Browsers may perform MIME-sniffing and execute malicious user uploads as executable code.",
                "penalty": 5
            })
            blueprint.append({
                "component": "MIME Sniffing",
                "action": "Add: X-Content-Type-Options: nosniff"
            })

        # Information disclosure leaks
        if headers_info.get("server_signature"):
            sig = headers_info["server_signature"]
            if any(char.isdigit() for char in sig): # e.g. Apache/2.4.41
                score -= 10
                issues.append({
                    "severity": "MODERATE",
                    "title": f"Server Version Leak Detected ({sig})",
                    "description": "Exact web server version is publicly broadcasted in HTTP responses, aiding automated exploit scanners.",
                    "penalty": 10
                })
                blueprint.append({
                    "component": "Server Token Obfuscation",
                    "action": "Configure server_tokens off; in Nginx, or ServerSignature Off in Apache."
                })

        # Exposed endpoints
        for ep in exposed_endpoints:
            pen = 15 if ep["risk"] == "HIGH" else 8
            score -= pen
            issues.append({
                "severity": ep["risk"],
                "title": f"Public Administrative Surface ({ep['path']})",
                "description": f"Endpoint {ep['path']} is accessible to public IP addresses without corporate IP whitelist or 2FA proxy.",
                "penalty": pen
            })
            blueprint.append({
                "component": f"Path Lockdown ({ep['path']})",
                "action": f"Restrict access to {ep['path']} using Cloudflare WAF Access Rule or IP allowlist."
            })

        score = max(5, min(100, score))

        # Assign Grade and Risk
        if score >= 90:
            grade, risk = "A+", "OPTIMAL"
        elif score >= 80:
            grade, risk = "A", "LOW"
        elif score >= 65:
            grade, risk = "B", "MODERATE"
        elif score >= 50:
            grade, risk = "C", "HIGH"
        else:
            grade, risk = "F", "CRITICAL"

        audit_token = str(uuid.uuid4())[:8]

        return {
            "domain": domain,
            "company_name": company_name,
            "overall_score": score,
            "security_grade": grade,
            "risk_level": risk,
            "detected_phone": headers_info.get("detected_phone"),
            "ssl_info": ssl_info,
            "headers_info": headers_info,
            "exposed_endpoints": exposed_endpoints,
            "issues": issues,
            "remediation_blueprint": blueprint,
            "audit_token": audit_token,
            "scanned_at": datetime.datetime.utcnow().isoformat()
        }

security_scanner = SecurityScanner()
