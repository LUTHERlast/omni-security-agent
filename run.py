import os
import sys
import uvicorn
from config import settings

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    port = int(os.environ.get("PORT", settings.PORT))
    host = os.environ.get("HOST", settings.HOST)

    print("=" * 65)
    print(f"[*] Launching {settings.APP_NAME} (Cyber Hygiene Engine)")
    print(f"[*] Dashboard & Command Center: http://127.0.0.1:{port}")
    print(f"[*] Health & Diagnostic API:   http://127.0.0.1:{port}/api/health")
    print(f"[*] Port:                      {port}")
    print(f"[*] Currency Mode:             AED (UAE Dirhams)")
    print("=" * 65)

    uvicorn.run("web.app:app", host=host, port=port, reload=False)
