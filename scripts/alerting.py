"""
scripts/alerting.py
=============================================================================
IoTGuard — Multi-Channel Alert System

PURPOSE:
    Send attack notifications via multiple channels (Email, Slack, Telegram)
    when the decision_loop detects threats.

CONFIGURATION (via environment variables):
    IOTGUARD_ALERTING_ENABLED=true
    
    # Email (SMTP)
    IOTGUARD_SMTP_HOST=smtp.gmail.com
    IOTGUARD_SMTP_PORT=587
    IOTGUARD_SMTP_USER=your_email@gmail.com
    IOTGUARD_SMTP_PASSWORD=your_app_password
    IOTGUARD_ALERT_EMAIL_TO=security@company.com
    
    # Slack
    IOTGUARD_SLACK_WEBHOOK=https://hooks.slack.com/services/...
    
    # Telegram
    IOTGUARD_TELEGRAM_TOKEN=your_bot_token
    IOTGUARD_TELEGRAM_CHAT_ID=your_chat_id

USAGE:
    from alerting import send_alert
    
    send_alert(
        title="Attack Detected",
        message="DDoS attack from 192.168.1.100",
        severity="high",
        src_ip="192.168.1.100"
    )
=============================================================================
"""

import os
import json
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, Dict, Any
import urllib.request
import urllib.error

logger = logging.getLogger("iotguard.alerting")

# =============================================================================
# Configuration (from environment variables)
# =============================================================================

def _get_config() -> Dict[str, Any]:
    """Load alerting configuration from environment variables."""
    return {
        "enabled": os.getenv("IOTGUARD_ALERTING_ENABLED", "false").lower() == "true",
        
        # Email/SMTP
        "smtp_host": os.getenv("IOTGUARD_SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": int(os.getenv("IOTGUARD_SMTP_PORT", "587")),
        "smtp_user": os.getenv("IOTGUARD_SMTP_USER", ""),
        "smtp_password": os.getenv("IOTGUARD_SMTP_PASSWORD", ""),
        "email_to": os.getenv("IOTGUARD_ALERT_EMAIL_TO", ""),
        "email_from": os.getenv("IOTGUARD_ALERT_EMAIL_FROM", "IoTGuard <alerts@iotguard.local>"),
        
        # Slack
        "slack_webhook": os.getenv("IOTGUARD_SLACK_WEBHOOK", ""),
        
        # Telegram
        "telegram_token": os.getenv("IOTGUARD_TELEGRAM_TOKEN", ""),
        "telegram_chat_id": os.getenv("IOTGUARD_TELEGRAM_CHAT_ID", ""),
        
        # Rate limiting (don't spam)
        "min_interval_seconds": int(os.getenv("IOTGUARD_ALERT_INTERVAL", "60")),
    }

# Track last alert time to prevent spam
_last_alert_time: float = 0.0


# =============================================================================
# Severity Configuration
# =============================================================================

SEVERITY_COLORS = {
    "critical": "#FF0000",  # Red
    "high": "#FF6600",      # Orange
    "medium": "#FFCC00",    # Yellow
    "low": "#00CC00",       # Green
    "info": "#0066CC",      # Blue
}

SEVERITY_EMOJI = {
    "critical": "🚨",
    "high": "⚠️",
    "medium": "⚡",
    "low": "ℹ️",
    "info": "📋",
}


# =============================================================================
# Email Alerting
# =============================================================================

def send_email_alert(
    title: str,
    message: str,
    severity: str = "medium",
    cfg: Optional[Dict] = None
) -> bool:
    """
    Send alert via SMTP email.
    
    Args:
        title: Alert subject line
        message: Alert body (can be HTML)
        severity: Alert severity level
        cfg: Configuration dict (uses env vars if None)
    
    Returns:
        True if email sent successfully
    """
    cfg = cfg or _get_config()
    
    if not cfg["smtp_user"] or not cfg["email_to"]:
        logger.debug("Email alerting not configured")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[IoTGuard] {SEVERITY_EMOJI.get(severity, '⚠️')} {title}"
        msg["From"] = cfg["email_from"]
        msg["To"] = cfg["email_to"]
        
        # Plain text version
        text_body = f"""
IoTGuard Security Alert
========================
Severity: {severity.upper()}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{message}
"""
        
        # HTML version
        color = SEVERITY_COLORS.get(severity, "#999999")
        html_body = f"""
<html>
<body style="font-family: Arial, sans-serif;">
<div style="border-left: 4px solid {color}; padding: 10px; margin: 10px 0;">
    <h2 style="color: {color}; margin: 0;">{SEVERITY_EMOJI.get(severity, '⚠️')} {title}</h2>
    <p style="color: #666; font-size: 12px;">
        Severity: <strong>{severity.upper()}</strong> | 
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </p>
</div>
<div style="padding: 10px;">
    <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px;">{message}</pre>
</div>
<hr style="border: none; border-top: 1px solid #eee;">
<p style="color: #999; font-size: 11px;">Sent by IoTGuard Intrusion Detection System</p>
</body>
</html>
"""
        
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))
        
        # Send via SMTP
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as server:
            server.starttls(context=context)
            server.login(cfg["smtp_user"], cfg["smtp_password"])
            server.sendmail(cfg["smtp_user"], cfg["email_to"], msg.as_string())
        
        logger.info(f"Email alert sent to {cfg['email_to']}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
        return False


# =============================================================================
# Slack Alerting
# =============================================================================

def send_slack_alert(
    title: str,
    message: str,
    severity: str = "medium",
    src_ip: Optional[str] = None,
    cfg: Optional[Dict] = None
) -> bool:
    """
    Send alert via Slack webhook.
    
    Args:
        title: Alert title
        message: Alert details
        severity: Alert severity level
        src_ip: Source IP of the attack
        cfg: Configuration dict
    
    Returns:
        True if message sent successfully
    """
    cfg = cfg or _get_config()
    webhook_url = cfg.get("slack_webhook", "")
    
    if not webhook_url:
        logger.debug("Slack webhook not configured")
        return False
    
    try:
        color = SEVERITY_COLORS.get(severity, "#999999")
        emoji = SEVERITY_EMOJI.get(severity, "⚠️")
        
        # Slack Block Kit message
        payload = {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} {title}",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                            {"type": "mrkdwn", "text": f"*Time:*\n{datetime.now().strftime('%H:%M:%S')}"},
                        ]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"```{message}```"}
                    }
                ]
            }]
        }
        
        if src_ip:
            payload["attachments"][0]["blocks"][1]["fields"].append(
                {"type": "mrkdwn", "text": f"*Source IP:*\n`{src_ip}`"}
            )
        
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                logger.info("Slack alert sent")
                return True
                
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")
    
    return False


# =============================================================================
# Telegram Alerting
# =============================================================================

def send_telegram_alert(
    title: str,
    message: str,
    severity: str = "medium",
    src_ip: Optional[str] = None,
    cfg: Optional[Dict] = None
) -> bool:
    """
    Send alert via Telegram bot.
    
    Args:
        title: Alert title
        message: Alert details
        severity: Alert severity level
        src_ip: Source IP of the attack
        cfg: Configuration dict
    
    Returns:
        True if message sent successfully
    """
    cfg = cfg or _get_config()
    token = cfg.get("telegram_token", "")
    chat_id = cfg.get("telegram_chat_id", "")
    
    if not token or not chat_id:
        logger.debug("Telegram not configured")
        return False
    
    try:
        emoji = SEVERITY_EMOJI.get(severity, "⚠️")
        
        # Format message for Telegram (Markdown)
        text = f"""
{emoji} *{title}*

*Severity:* {severity.upper()}
*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        if src_ip:
            text += f"*Source IP:* `{src_ip}`\n"
        
        text += f"\n```\n{message}\n```"
        
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                logger.info("Telegram alert sent")
                return True
                
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")
    
    return False


# =============================================================================
# Main Alert Function
# =============================================================================

def send_alert(
    title: str,
    message: str,
    severity: str = "medium",
    src_ip: Optional[str] = None,
    force: bool = False
) -> Dict[str, bool]:
    """
    Send alert via all configured channels.
    
    This is the main entry point for sending alerts. It will:
    1. Check if alerting is enabled
    2. Respect rate limiting (unless force=True)
    3. Send to all configured channels
    
    Args:
        title: Alert title
        message: Alert details
        severity: Alert severity (critical, high, medium, low, info)
        src_ip: Source IP of the attack
        force: If True, bypass rate limiting
    
    Returns:
        Dict with channel names as keys and success status as values
        
    Example:
        results = send_alert(
            title="DDoS Attack Detected",
            message="High volume SYN flood from 192.168.1.100",
            severity="high",
            src_ip="192.168.1.100"
        )
        # results = {"email": True, "slack": True, "telegram": False}
    """
    import time
    global _last_alert_time
    
    cfg = _get_config()
    results = {"email": False, "slack": False, "telegram": False}
    
    # Check if alerting is enabled
    if not cfg["enabled"]:
        logger.debug("Alerting is disabled")
        return results
    
    # Rate limiting
    now = time.time()
    if not force and (now - _last_alert_time) < cfg["min_interval_seconds"]:
        logger.debug(f"Rate limited (last alert was {now - _last_alert_time:.0f}s ago)")
        return results
    
    _last_alert_time = now
    
    # Send to all channels
    results["email"] = send_email_alert(title, message, severity, cfg)
    results["slack"] = send_slack_alert(title, message, severity, src_ip, cfg)
    results["telegram"] = send_telegram_alert(title, message, severity, src_ip, cfg)
    
    # Log summary
    sent = [k for k, v in results.items() if v]
    if sent:
        logger.info(f"Alert sent via: {', '.join(sent)}")
    else:
        logger.warning("No alerts were sent (no channels configured?)")
    
    return results


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("Testing IoTGuard Alerting System")
    print("=" * 40)
    
    # Test alert
    results = send_alert(
        title="Test Alert",
        message="This is a test alert from IoTGuard.",
        severity="info",
        src_ip="192.168.1.100",
        force=True
    )
    
    print(f"Results: {results}")
