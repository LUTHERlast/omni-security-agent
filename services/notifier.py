import datetime
from typing import Optional, Dict
import httpx
from config import settings
from database import AsyncSessionLocal
from models import SecurityEvent

class TelegramNotifier:
    """Dispatches real-time push alerts to operator's Telegram channel."""

    def __init__(self):
        self.bot_token = settings.TELEGRAM_BOT_TOKEN
        self.chat_id = settings.TELEGRAM_CHAT_ID

    async def log_event(self, level: str, category: str, message: str, details: Optional[str] = None):
        """Persists event to local audit log and fires Telegram alert if configured."""
        try:
            async with AsyncSessionLocal() as session:
                event = SecurityEvent(
                    level=level,
                    category=category,
                    message=message[:490],
                    details=details
                )
                session.add(event)
                await session.commit()
        except Exception as e:
            print(f"[Notifier Log Error] {e}")

        # Send Telegram message
        if settings.NOTIFY_TELEGRAM and self.bot_token and self.chat_id:
            try:
                emoji = "🛡️"
                if level == "CRITICAL": emoji = "🚨"
                elif level == "SUCCESS": emoji = "💰"
                elif level == "WARNING": emoji = "⚠️"

                text = f"{emoji} <b>[OmniSecurity AI]</b>\n\n{message}"
                if details:
                    text += f"\n\n<code>{details[:400]}</code>"

                url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
                async with httpx.AsyncClient(timeout=4.0) as client:
                    await client.post(url, json={
                        "chat_id": self.chat_id,
                        "text": text,
                        "parse_mode": "HTML"
                    })
            except Exception:
                pass

notifier = TelegramNotifier()
