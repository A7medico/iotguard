"""
scripts/alerts.py
=============================================================================
IoTGuard — Multi-Channel Alert System
=============================================================================

PIPELINE POSITION:
    ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
    │ decision_loop.py│ --> │   alerts.py     │ --> │ Email / Slack   │
    │ (threat detect) │     │ (this file)     │     │ (notifications) │
    └─────────────────┘     └─────────────────┘     └─────────────────┘

HOW IT WORKS:
    1. When decision_loop.py detects a threat, it calls send_threat_alert()
    2. AlertManager checks if the severity meets the minimum threshold
    3. If yes, it sends notifications through all configured channels:
       - Console logging (always enabled)
       - Email via SMTP (if IOTGUARD_SMTP_* env vars are set)
       - Slack via webhook (if IOTGUARD_SLACK_WEBHOOK is set)

CONFIGURATION:
    All configuration is via environment variables (no hardcoded secrets):
    
    Email Setup:
        IOTGUARD_SMTP_HOST     : SMTP server (e.g., smtp.gmail.com)
        IOTGUARD_SMTP_PORT     : SMTP port (default: 587 for TLS)
        IOTGUARD_SMTP_USER     : Your email address
        IOTGUARD_SMTP_PASS     : App password (NOT your regular password!)
        IOTGUARD_SMTP_TO       : Where to send alerts
    
    Slack Setup:
        IOTGUARD_SLACK_WEBHOOK : Incoming webhook URL from Slack app
    
    Alert Filtering:
        IOTGUARD_ALERT_MIN_SEVERITY : low/medium/high/critical (default: medium)

USAGE EXAMPLES:
    # Basic usage - send a threat alert
    from alerts import send_threat_alert
    send_threat_alert(ip="192.168.1.100", score=0.95, attack_type="SYN_Flood")
    
    # Advanced usage - custom alerts
    from alerts import AlertManager
    manager = AlertManager()
    manager.send_alert(
        title="Custom Alert",
        message="Something happened",
        severity="high",
        metadata={"key": "value"}
    )
    
    # Test all configured channels
    manager.test_channels()

SECURITY NOTES:
    - Never commit credentials to git! Use environment variables.
    - For Gmail, use "App Passwords" (not your main password)
    - Slack webhooks should be kept secret and rotated periodically
=============================================================================
"""

import os
import json
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any
from datetime import datetime

# ============================================================================
# OPTIONAL DEPENDENCY: requests (for Slack webhooks)
# If not installed, Slack alerts will be disabled but everything else works
# ============================================================================
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Get logger for this module (configured in logging_config.py)
logger = logging.getLogger("iotguard.alerts")


class AlertManager:
    """
    Multi-channel alert manager for IoTGuard threat notifications.
    
    This class handles sending alerts through multiple channels:
    - Console (always enabled via Python logging)
    - Email (SMTP, optional)
    - Slack (webhook, optional)
    
    ARCHITECTURE:
        AlertManager
        ├── send_alert()          # Main entry point
        │   ├── _should_alert()   # Check severity threshold
        │   ├── _send_email()     # SMTP channel
        │   └── _send_slack()     # Webhook channel
        └── test_channels()       # Verify configuration
    
    THREAD SAFETY:
        This class is thread-safe. Multiple threads can call send_alert()
        simultaneously without issues.
    """
    
    def __init__(self):
        """
        Initialize the alert manager by reading configuration from environment.
        
        ENVIRONMENT VARIABLES READ:
            IOTGUARD_SMTP_HOST     : SMTP server hostname
            IOTGUARD_SMTP_PORT     : SMTP port (default: 587)
            IOTGUARD_SMTP_USER     : Email username
            IOTGUARD_SMTP_PASS     : Email password
            IOTGUARD_SMTP_TO       : Recipient email
            IOTGUARD_SLACK_WEBHOOK : Slack webhook URL
            IOTGUARD_ALERT_MIN_SEVERITY : Minimum severity to alert
        
        EXAMPLE:
            # Set environment variables first
            os.environ["IOTGUARD_SMTP_HOST"] = "smtp.gmail.com"
            os.environ["IOTGUARD_SMTP_USER"] = "myemail@gmail.com"
            
            # Then create the manager
            manager = AlertManager()
        """
        # -------------------------------------------------------------------
        # EMAIL CONFIGURATION
        # All values come from environment variables for security
        # -------------------------------------------------------------------
        self.smtp_host = os.getenv("IOTGUARD_SMTP_HOST", "")
        self.smtp_port = int(os.getenv("IOTGUARD_SMTP_PORT", "587"))
        self.smtp_user = os.getenv("IOTGUARD_SMTP_USER", "")
        self.smtp_pass = os.getenv("IOTGUARD_SMTP_PASS", "")
        self.smtp_to = os.getenv("IOTGUARD_SMTP_TO", "")
        
        # -------------------------------------------------------------------
        # SLACK CONFIGURATION
        # Webhook URL obtained from: Slack App > Incoming Webhooks
        # -------------------------------------------------------------------
        self.slack_webhook = os.getenv("IOTGUARD_SLACK_WEBHOOK", "")
        
        # -------------------------------------------------------------------
        # ALERT FILTERING
        # Only send alerts if severity >= min_severity
        # This prevents alert fatigue from low-severity events
        # -------------------------------------------------------------------
        self.min_severity = os.getenv("IOTGUARD_ALERT_MIN_SEVERITY", "medium")
        
        # -------------------------------------------------------------------
        # CHANNEL STATUS
        # Determine which channels are properly configured
        # -------------------------------------------------------------------
        # Email requires: host, user, password, and recipient
        self.email_enabled = all([
            self.smtp_host, 
            self.smtp_user, 
            self.smtp_pass, 
            self.smtp_to
        ])
        
        # Slack requires: webhook URL AND requests library
        self.slack_enabled = bool(self.slack_webhook) and REQUESTS_AVAILABLE
        
        # -------------------------------------------------------------------
        # STARTUP LOGGING
        # Log which channels are enabled for debugging
        # -------------------------------------------------------------------
        if self.email_enabled:
            logger.info("📧 Email alerts enabled")
        if self.slack_enabled:
            logger.info("💬 Slack alerts enabled")
        if not self.email_enabled and not self.slack_enabled:
            logger.info("🔕 No external alert channels configured (console only)")
    
    def _severity_to_level(self, severity: str) -> int:
        """
        Convert severity string to numeric level for comparison.
        
        SEVERITY LEVELS:
            low      = 1  (informational)
            medium   = 2  (warning, default threshold)
            high     = 3  (urgent)
            critical = 4  (immediate action required)
        
        Args:
            severity: String like "low", "high", "critical"
            
        Returns:
            Integer level (1-4)
        """
        levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return levels.get(severity.lower(), 2)  # Default to medium
    
    def _should_alert(self, severity: str) -> bool:
        """
        Check if alert should be sent based on minimum severity threshold.
        
        This prevents alert fatigue by filtering out low-priority events.
        
        EXAMPLE:
            If min_severity = "high":
                - "low" events -> NOT sent
                - "medium" events -> NOT sent  
                - "high" events -> SENT
                - "critical" events -> SENT
        
        Args:
            severity: The severity of the current alert
            
        Returns:
            True if alert should be sent, False to suppress
        """
        return self._severity_to_level(severity) >= self._severity_to_level(self.min_severity)
    
    def _get_emoji(self, severity: str) -> str:
        """
        Get appropriate emoji for severity level.
        
        Used in both console output and Slack messages.
        
        Returns:
            Emoji string
        """
        emojis = {
            "low": "🟡",      # Yellow circle
            "medium": "🟠",   # Orange circle
            "high": "🔴",     # Red circle
            "critical": "🚨"  # Siren
        }
        return emojis.get(severity.lower(), "⚠️")  # Default warning
    
    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, bool]:
        """
        Send alert through all configured channels.
        
        FLOW:
            1. Check if severity meets threshold
            2. Log to console (always)
            3. Send email if configured
            4. Send Slack if configured
            5. Return success status for each channel
        
        Args:
            title: Alert title (used as email subject, Slack header)
            message: Main alert body text
            severity: low, medium, high, or critical
            metadata: Additional context dict (IP, score, etc.)
            
        Returns:
            Dict like {"console": True, "email": True, "slack": False}
            
        EXAMPLE:
            results = manager.send_alert(
                title="SYN Flood Detected",
                message="High volume of SYN packets from 10.0.0.50",
                severity="high",
                metadata={"source_ip": "10.0.0.50", "pps": 50000}
            )
            if results["email"]:
                print("Email sent successfully!")
        """
        # Default results - console always succeeds
        results = {"console": True, "email": False, "slack": False}
        
        # -------------------------------------------------------------------
        # STEP 1: Check severity threshold
        # Skip everything if below minimum severity
        # -------------------------------------------------------------------
        if not self._should_alert(severity):
            logger.debug(f"Alert suppressed (below threshold): {title}")
            return results
        
        # -------------------------------------------------------------------
        # STEP 2: Prepare common data
        # -------------------------------------------------------------------
        timestamp = datetime.now().isoformat()
        emoji = self._get_emoji(severity)
        
        # -------------------------------------------------------------------
        # STEP 3: Console logging (always enabled)
        # This ensures alerts are captured even if external channels fail
        # -------------------------------------------------------------------
        logger.warning(f"{emoji} ALERT [{severity.upper()}]: {title} - {message}")
        
        # -------------------------------------------------------------------
        # STEP 4: Email channel (if configured)
        # -------------------------------------------------------------------
        if self.email_enabled:
            results["email"] = self._send_email(
                title, message, severity, metadata, timestamp
            )
        
        # -------------------------------------------------------------------
        # STEP 5: Slack channel (if configured)
        # -------------------------------------------------------------------
        if self.slack_enabled:
            results["slack"] = self._send_slack(
                title, message, severity, metadata, timestamp
            )
        
        return results
    
    def _send_email(
        self,
        title: str,
        message: str,
        severity: str,
        metadata: Optional[Dict[str, Any]],
        timestamp: str
    ) -> bool:
        """
        Send email alert via SMTP.
        
        WORKFLOW:
            1. Create MIME message (both text and HTML versions)
            2. Connect to SMTP server with TLS
            3. Authenticate
            4. Send the message
            5. Close connection
        
        SECURITY:
            - Uses STARTTLS for encryption
            - Password comes from environment (never hardcoded)
        
        Args:
            title: Email subject line
            message: Body text
            severity: For color coding in HTML
            metadata: Extra data to include
            timestamp: ISO format timestamp
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # ---------------------------------------------------------------
            # Create multipart message (text + HTML versions)
            # Email clients will display the best version they support
            # ---------------------------------------------------------------
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[IoTGuard {severity.upper()}] {title}"
            msg["From"] = self.smtp_user
            msg["To"] = self.smtp_to
            
            # ---------------------------------------------------------------
            # PLAIN TEXT VERSION
            # For email clients that don't support HTML
            # ---------------------------------------------------------------
            text_body = f"""
IoTGuard Security Alert
=======================
Time: {timestamp}
Severity: {severity.upper()}
Title: {title}

{message}

Metadata:
{json.dumps(metadata or {}, indent=2)}

--
IoTGuard Intrusion Detection System
            """
            
            # ---------------------------------------------------------------
            # HTML VERSION
            # Rich formatting with colors based on severity
            # ---------------------------------------------------------------
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <div style="background: {'#ff4444' if severity in ['high', 'critical'] else '#ff8800'}; 
                            color: white; padding: 15px; border-radius: 5px;">
                    <h2 style="margin: 0;">{self._get_emoji(severity)} IoTGuard Alert: {title}</h2>
                </div>
                <div style="padding: 20px; background: #f5f5f5; margin-top: 10px; border-radius: 5px;">
                    <p><strong>Time:</strong> {timestamp}</p>
                    <p><strong>Severity:</strong> {severity.upper()}</p>
                    <p><strong>Message:</strong> {message}</p>
                    <pre style="background: #333; color: #0f0; padding: 10px; border-radius: 3px;">
{json.dumps(metadata or {}, indent=2)}
                    </pre>
                </div>
            </body>
            </html>
            """
            
            # Attach both versions
            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))
            
            # ---------------------------------------------------------------
            # SEND VIA SMTP
            # Use context manager to ensure connection is closed
            # ---------------------------------------------------------------
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()  # Upgrade to encrypted connection
                server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.smtp_user, self.smtp_to, msg.as_string())
            
            logger.info(f"📧 Email alert sent to {self.smtp_to}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _send_slack(
        self,
        title: str,
        message: str,
        severity: str,
        metadata: Optional[Dict[str, Any]],
        timestamp: str
    ) -> bool:
        """
        Send Slack alert via webhook.
        
        SLACK WEBHOOK SETUP:
            1. Go to api.slack.com/apps
            2. Create new app or select existing
            3. Enable "Incoming Webhooks"
            4. Add webhook to your channel
            5. Copy the webhook URL
            6. Set IOTGUARD_SLACK_WEBHOOK env var
        
        MESSAGE FORMAT:
            Uses Slack's attachment format with:
            - Color bar based on severity
            - Title with emoji
            - Fields for structured data
            - Timestamp footer
        
        Args:
            title: Alert title
            message: Body text
            severity: For color selection
            metadata: Additional fields
            timestamp: ISO timestamp
            
        Returns:
            True if sent successfully
        """
        try:
            # Color map: Slack uses hex colors for attachment bars
            color = {
                "low": "#ffcc00",      # Yellow
                "medium": "#ff8800",   # Orange
                "high": "#ff4444",     # Red
                "critical": "#cc0000"  # Dark red
            }.get(severity.lower(), "#808080")
            
            # ---------------------------------------------------------------
            # BUILD SLACK PAYLOAD
            # Uses attachments for rich formatting
            # ---------------------------------------------------------------
            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"{self._get_emoji(severity)} {title}",
                    "text": message,
                    "fields": [
                        {"title": "Severity", "value": severity.upper(), "short": True},
                        {"title": "Time", "value": timestamp, "short": True}
                    ],
                    "footer": "IoTGuard IDS",
                    "ts": datetime.now().timestamp()
                }]
            }
            
            # Add metadata as additional fields (max 5 to avoid clutter)
            if metadata:
                for key, value in list(metadata.items())[:5]:
                    payload["attachments"][0]["fields"].append({
                        "title": key.replace("_", " ").title(),
                        "value": str(value),
                        "short": True
                    })
            
            # ---------------------------------------------------------------
            # SEND HTTP POST
            # Webhook returns "ok" on success
            # ---------------------------------------------------------------
            response = requests.post(
                self.slack_webhook,
                json=payload,
                timeout=10  # 10 second timeout
            )
            
            if response.status_code == 200:
                logger.info("💬 Slack alert sent")
                return True
            else:
                logger.error(f"Slack webhook returned {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False
    
    def test_channels(self) -> Dict[str, bool]:
        """
        Send test alert to all configured channels.
        
        USE CASE:
            Call this after setting up configuration to verify
            everything is working correctly.
        
        EXAMPLE:
            manager = AlertManager()
            results = manager.test_channels()
            print(f"Email working: {results['email']}")
            print(f"Slack working: {results['slack']}")
        
        Returns:
            Dict with success status for each channel
        """
        return self.send_alert(
            title="Test Alert",
            message="This is a test alert from IoTGuard",
            severity="low",  # Use low to avoid scaring anyone!
            metadata={"test": True}
        )


# ============================================================================
# SINGLETON PATTERN
# Single global instance for convenient import
# ============================================================================
_alert_manager: Optional[AlertManager] = None

def get_alert_manager() -> AlertManager:
    """
    Get or create the global AlertManager instance.
    
    USAGE:
        from alerts import get_alert_manager
        manager = get_alert_manager()
        manager.send_alert(...)
    
    WHY SINGLETON:
        - AlertManager reads config on init (only need to do once)
        - Avoids creating multiple SMTP connections
        - Consistent state across the application
    
    Returns:
        The global AlertManager instance
    """
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager


def send_threat_alert(
    ip: str,
    score: float,
    attack_type: str = "Unknown",
    blocked: bool = False
) -> Dict[str, bool]:
    """
    Convenience function for sending threat detection alerts.
    
    USAGE:
        This is the main function called by decision_loop.py when
        a threat is detected.
    
    EXAMPLE:
        from alerts import send_threat_alert
        
        # When a threat is detected:
        send_threat_alert(
            ip="192.168.1.100",
            score=0.95,
            attack_type="SYN_Flood",
            blocked=True
        )
    
    SEVERITY MAPPING (automatic based on score):
        score >= 0.9  -> critical
        score >= 0.7  -> high
        score >= 0.5  -> medium
        score <  0.5  -> low
    
    Args:
        ip: Source IP address of the threat
        score: Detection confidence (0.0 to 1.0)
        attack_type: Type of attack detected (e.g., "DDoS", "PortScan")
        blocked: Whether the IP was blocked
        
    Returns:
        Dict with success status for each channel
    """
    manager = get_alert_manager()
    
    # -----------------------------------------------------------------------
    # AUTO-DETERMINE SEVERITY FROM SCORE
    # Higher scores = more certain of attack = higher severity
    # -----------------------------------------------------------------------
    if score >= 0.9:
        severity = "critical"
    elif score >= 0.7:
        severity = "high"
    elif score >= 0.5:
        severity = "medium"
    else:
        severity = "low"
    
    action = "BLOCKED" if blocked else "DETECTED"
    
    return manager.send_alert(
        title=f"Threat {action}: {attack_type}",
        message=f"Source IP {ip} detected with score {score:.2%}",
        severity=severity,
        metadata={
            "source_ip": ip,
            "score": round(score, 4),
            "attack_type": attack_type,
            "blocked": blocked
        }
    )


# ============================================================================
# STANDALONE TESTING
# Run this file directly to test alert configuration
# ============================================================================
if __name__ == "__main__":
    # Basic logging setup for testing
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )
    
    print("=" * 60)
    print("IoTGuard Alert System Test")
    print("=" * 60)
    
    manager = AlertManager()
    
    print(f"\nChannel Status:")
    print(f"  Email enabled: {manager.email_enabled}")
    print(f"  Slack enabled: {manager.slack_enabled}")
    print(f"  Min severity:  {manager.min_severity}")
    
    print("\nSending test alert...")
    results = manager.test_channels()
    
    print(f"\nResults:")
    for channel, success in results.items():
        status = "✅" if success else "❌"
        print(f"  {channel}: {status}")
