"""
HF Guardian - Continuous Integrity & Intrusion Monitoring Engine
Periodically inspects targets (Websites and Hugging Face repositories)
for tampering, defacement, unauthorized commits, injected backdoors, and outages.
"""

import time
import uuid
import asyncio
import hashlib
import re
import urllib.request
import urllib.error
import json
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any
from enum import Enum

from scanner import HFScanner, Severity

class TargetType(str, Enum):
    WEBSITE = "website"
    API = "api"
    MODEL = "model"
    HUGGINGFACE = "huggingface"

class TargetStatus(str, Enum):
    HEALTHY = "HEALTHY"
    COMPROMISED = "COMPROMISED"
    SCANNING = "SCANNING"
    WARNING = "WARNING"
    DOWN = "DOWN"
    PENDING = "PENDING"

class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    WARNING = "WARNING"
    INFO = "INFO"

@dataclass
class Alert:
    id: str
    target_id: str
    target_name: str
    target_type: str
    severity: str
    title: str
    message: str
    evidence: List[str]
    timestamp: float = field(default_factory=time.time)
    acknowledged: bool = False

@dataclass
class Target:
    id: str
    name: str
    target_type: str  # website or huggingface
    url_or_repo: str
    interval_seconds: int = 30
    status: str = TargetStatus.PENDING.value
    last_scanned: Optional[float] = None
    next_scan: Optional[float] = None
    webhook_url: Optional[str] = None
    alert_emails: Optional[str] = None
    baseline: Dict[str, Any] = field(default_factory=dict)
    last_findings: List[str] = field(default_factory=list)
    last_alert_time: float = 0.0
    last_alert_title: str = ""
    created_at: float = field(default_factory=time.time)

# Common indicators of web compromise/defacement
DEFACEMENT_INDICATORS = [
    (re.compile(r'(?i)hacked\s+by'), "Defacement Signature (Hacked By)"),
    (re.compile(r'(?i)pwned\s+by'), "Defacement Signature (Pwned By)"),
    (re.compile(r'(?i)c99shell|r57shell|b374k|wso\s+shell'), "Known Web Shell Header"),
    (re.compile(r'eval\(base64_decode\('), "PHP Web Shell Obfuscation"),
    (re.compile(r'(?i)coinhive\.min\.js|cryptonight|coin-hive'), "Cryptocurrency Miner Script Injection"),
    (re.compile(r'(?i)<iframe[^>]+(display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["\']?0)["\']?'), "Hidden Malicious Iframe"),
    (re.compile(r'document\.write\(unescape\('), "Obfuscated DOM Injection"),
    (re.compile(r'(?i)<script[^>]*src=["\']https?://[a-z0-9\-]+\.(cc|tk|ru|top|pw|xyz)/'), "Suspicious External Script Domain"),
]

class ContinuousMonitoringEngine:
    def __init__(self):
        self.targets: Dict[str, Target] = {}
        self.alerts: List[Alert] = []
        self.scanner = HFScanner()
        self.subscribers: List[asyncio.Queue] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def add_target(self, name: str, target_type: str, url_or_repo: str, interval_seconds: int = 30, webhook_url: Optional[str] = None, alert_emails: Optional[str] = None) -> Target:
        target_id = str(uuid.uuid4())[:8]
        # Normalize
        url_or_repo = url_or_repo.strip()
        if target_type in (TargetType.WEBSITE.value, TargetType.API.value):
            if not url_or_repo.startswith("http://") and not url_or_repo.startswith("https://"):
                url_or_repo = "https://" + url_or_repo
        elif target_type in (TargetType.MODEL.value, TargetType.HUGGINGFACE.value):
            # strip https://huggingface.co/ if entered as full URL
            if "huggingface.co/" in url_or_repo:
                url_or_repo = url_or_repo.replace("https://huggingface.co/", "").replace("http://huggingface.co/", "").strip("/")

        target = Target(
            id=target_id,
            name=name or url_or_repo,
            target_type=target_type,
            url_or_repo=url_or_repo,
            interval_seconds=max(5, interval_seconds),
            next_scan=time.time(),
            webhook_url=webhook_url or None,
            alert_emails=alert_emails.strip() if alert_emails else None
        )
        self.targets[target_id] = target
        self._broadcast({"type": "target_added", "target": asdict(target)})
        return target

    def update_target(
        self,
        target_id: str,
        name: Optional[str] = None,
        target_type: Optional[str] = None,
        url_or_repo: Optional[str] = None,
        interval_seconds: Optional[int] = None,
        webhook_url: Optional[str] = None,
        alert_emails: Optional[str] = None
    ) -> Optional[Target]:
        target = self.targets.get(target_id)
        if not target:
            return None
        if name is not None and name.strip():
            target.name = name.strip()
        if target_type is not None and target_type.strip():
            target.target_type = target_type.strip()
        if url_or_repo is not None and url_or_repo.strip():
            u = url_or_repo.strip()
            if target.target_type in (TargetType.WEBSITE.value, TargetType.API.value) and not u.startswith(("http://", "https://")):
                u = "https://" + u
            elif target.target_type in (TargetType.MODEL.value, TargetType.HUGGINGFACE.value):
                if "huggingface.co/" in u:
                    u = u.replace("https://huggingface.co/", "").replace("http://huggingface.co/", "").strip("/")
            if target.url_or_repo != u:
                target.url_or_repo = u
                target.baseline = {}
                target.status = TargetStatus.PENDING.value
        if interval_seconds is not None:
            target.interval_seconds = max(5, int(interval_seconds))
            target.next_scan = time.time() + target.interval_seconds
        if webhook_url is not None:
            target.webhook_url = webhook_url.strip() or None
        if alert_emails is not None:
            target.alert_emails = alert_emails.strip() or None
        self._broadcast({"type": "target_updated", "target": asdict(target)})
        return target

    def remove_target(self, target_id: str) -> bool:
        if target_id in self.targets:
            del self.targets[target_id]
            # Also purge any alerts that were associated with this target
            self.alerts = [a for a in self.alerts if a.target_id != target_id]
            self._broadcast({"type": "target_removed", "target_id": target_id})
            return True
        return False

    def get_targets(self) -> List[Dict[str, Any]]:
        return [asdict(t) for t in self.targets.values()]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        # Sort newest first
        sorted_alerts = sorted(self.alerts, key=lambda a: a.timestamp, reverse=True)
        return [asdict(a) for a in sorted_alerts[:limit]]

    def acknowledge_alert(self, alert_id: str) -> bool:
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                self._broadcast({"type": "alert_acknowledged", "alert_id": alert_id})
                return True
        return False

    def clear_alerts(self):
        self.alerts.clear()
        self._broadcast({"type": "alerts_cleared"})

    def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue()
        self.subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self.subscribers:
            self.subscribers.remove(q)

    def _broadcast(self, event_data: dict):
        for q in list(self.subscribers):
            try:
                q.put_nowait(event_data)
            except Exception:
                pass

    def emit_alert(self, target: Target, severity: AlertSeverity, title: str, message: str, evidence: List[str], target_status: Optional[str] = None) -> Alert:
        alert = Alert(
            id=str(uuid.uuid4())[:8],
            target_id=target.id,
            target_name=target.name,
            target_type=target.target_type,
            severity=severity.value,
            title=title,
            message=message,
            evidence=evidence,
            timestamp=time.time(),
            acknowledged=False
        )
        self.alerts.append(alert)
        if target_status:
            target.status = target_status
        else:
            target.status = TargetStatus.COMPROMISED.value if severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH) else TargetStatus.WARNING.value
        
        # Broadcast via SSE
        self._broadcast({
            "type": "new_alert",
            "alert": asdict(alert),
            "target": asdict(target)
        })

        # Send Webhook asynchronously if configured
        if target.webhook_url:
            asyncio.create_task(self._send_webhook(target.webhook_url, alert))

        # Dispatch real-time SMTP Email notification (immediate on first alert, throttled while unchanged)
        now = time.time()
        last_t = getattr(target, 'last_alert_time', 0.0) or 0.0
        last_title = getattr(target, 'last_alert_title', '') or ''

        if (now - last_t > 180) or (last_title != title):
            target.last_alert_time = now
            target.last_alert_title = title
            try:
                from email_service import send_alert_email_async
                recipients = []
                if target.alert_emails:
                    recipients = [e.strip() for e in target.alert_emails.split(",") if e.strip()]
                if not recipients:
                    recipients = [None]  # Uses default ALERT_RECIPIENT

                for rcpt in recipients:
                    asyncio.create_task(send_alert_email_async(
                        target_name=target.name,
                        target_url=target.url_or_repo,
                        severity=alert.severity,
                        alert_title=alert.title,
                        message=alert.message,
                        evidence=alert.evidence,
                        recipient=rcpt
                    ))
            except Exception as err:
                print(f"[Alert Email Error] {err}")

        return alert

    async def _send_webhook(self, webhook_url: str, alert: Alert):
        try:
            payload = json.dumps({
                "source": "HF-Guardian-Sentinel",
                "event": "SECURITY_COMPROMISE_DETECTED",
                "severity": alert.severity,
                "target": alert.target_name,
                "title": alert.title,
                "message": alert.message,
                "evidence": alert.evidence,
                "timestamp": alert.timestamp
            }).encode('utf-8')
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "HFGuardian-Sentinel/1.0"}
            )
            await asyncio.to_thread(urllib.request.urlopen, req, timeout=5)
        except Exception as e:
            print(f"[Webhook Error] Failed to send alert webhook to {webhook_url}: {e}")

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self):
        while self._running:
            now = time.time()
            for target_id, target in list(self.targets.items()):
                if target.next_scan and now >= target.next_scan:
                    target.next_scan = now + target.interval_seconds
                    asyncio.create_task(self.scan_target(target))
            await asyncio.sleep(1)

    async def scan_target(self, target: Target):
        target.status = TargetStatus.SCANNING.value
        self._broadcast({"type": "target_updated", "target": asdict(target)})

        try:
            if target.target_type in (TargetType.WEBSITE.value, TargetType.API.value):
                await self._scan_website(target)
            elif target.target_type in (TargetType.MODEL.value, TargetType.HUGGINGFACE.value):
                if target.url_or_repo.startswith(("http://", "https://")):
                    await self._scan_website(target)
                else:
                    await self._scan_huggingface(target)
            else:
                await self._scan_website(target)
        except Exception as e:
            err_str = str(e)
            if "111" in err_str or "Connection refused" in err_str:
                clean_err = "Service Offline: Connection refused (Process stopped or port unreachable)."
            elif "timed out" in err_str.lower():
                clean_err = "Service Timeout: Endpoint did not respond within 10 seconds."
            else:
                clean_err = f"Service Outage: {err_str}"

            target.status = TargetStatus.DOWN.value
            target.last_findings = [clean_err]

            # Only emit ONE alert when entering outage state to prevent duplicate alert spam every 10s
            if getattr(target, 'last_alert_title', '') != "Service Offline / Unreachable":
                self.emit_alert(
                    target,
                    AlertSeverity.HIGH,
                    "Service Offline / Unreachable",
                    f"Target {target.name} ({target.url_or_repo}) is currently offline.",
                    [clean_err],
                    target_status=TargetStatus.DOWN.value
                )

        target.last_scanned = time.time()
        target.next_scan = time.time() + target.interval_seconds
        self._broadcast({"type": "target_updated", "target": asdict(target)})

    async def _scan_website(self, target: Target):
        url = target.url_or_repo
        start_t = time.time()
        
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 HF-Guardian/1.0"
            }
        )

        def _fetch():
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read()
                return resp.status, dict(resp.headers), content

        try:
            status_code, headers, body = await asyncio.to_thread(_fetch)
        except urllib.error.HTTPError as e:
            status_code = e.code
            body = e.read() if hasattr(e, 'read') else b""
            headers = dict(e.headers) if hasattr(e, 'headers') else {}
            if status_code in (500, 502, 503, 504):
                clean_err = f"Service Outage (HTTP {status_code}): Server error response."
                target.status = TargetStatus.DOWN.value
                target.last_findings = [clean_err]
                if getattr(target, 'last_alert_title', '') != f"HTTP {status_code} Outage":
                    self.emit_alert(
                        target,
                        AlertSeverity.HIGH,
                        f"HTTP {status_code} Outage",
                        f"Target {target.name} ({url}) returned server error HTTP {status_code}.",
                        [clean_err],
                        target_status=TargetStatus.DOWN.value
                    )
                return
        except Exception as e:
            err_str = str(e)
            if "111" in err_str or "Connection refused" in err_str:
                clean_err = "Service Offline: Connection refused (Process stopped or port unreachable)."
            elif "timed out" in err_str.lower():
                clean_err = "Service Timeout: Endpoint did not respond within 10 seconds."
            else:
                clean_err = f"Service Outage: {err_str}"

            target.status = TargetStatus.DOWN.value
            target.last_findings = [clean_err]

            # Only emit ONE alert when entering outage state to prevent duplicate alert spam
            if getattr(target, 'last_alert_title', '') != "Service Offline / Unreachable":
                self.emit_alert(
                    target,
                    AlertSeverity.HIGH,
                    "Service Offline / Unreachable",
                    f"Target {target.name} ({url}) is currently offline.",
                    [clean_err],
                    target_status=TargetStatus.DOWN.value
                )
            return

        elapsed = round((time.time() - start_t) * 1000, 2)
        body_hash = hashlib.sha256(body).hexdigest()
        text_content = body.decode('utf-8', errors='replace')

        findings = []
        is_hacked = False

        # 1. Defacement and Malicious Code Inspection
        for pattern, label in DEFACEMENT_INDICATORS:
            match = pattern.search(text_content)
            if match:
                is_hacked = True
                snippet = match.group(0)[:120]
                findings.append(f"INJECTION DETECTED: {label} -> `{snippet}`")
                self.emit_alert(
                    target,
                    AlertSeverity.CRITICAL,
                    f"Active Hack Detected: {label}",
                    f"Malicious payload or defacement pattern matched on {url}.",
                    [f"Pattern matched: {label}", f"Evidence snippet: {snippet}"]
                )

        # 2. Baseline Comparison / Unauthorized Modification Check
        if "body_hash" not in target.baseline:
            # Initialize baseline on first healthy scan
            target.baseline = {
                "body_hash": body_hash,
                "status_code": status_code,
                "size_bytes": len(body),
                "last_modified": headers.get("Last-Modified") or headers.get("Date"),
            }
            findings.append(f"Security baseline initialized (SHA: {body_hash[:8]}..., Status: {status_code})")
        else:
            prev_hash = target.baseline.get("body_hash")
            prev_size = target.baseline.get("size_bytes", 0)

            if body_hash != prev_hash:
                size_diff = len(body) - prev_size
                diff_msg = f"Size changed by {size_diff:+d} bytes. Hash: {prev_hash[:8]} -> {body_hash[:8]}"
                findings.append(f"Page integrity changed! {diff_msg}")

                # If large unexpected delta or not acknowledged
                if not is_hacked:
                    self.emit_alert(
                        target,
                        AlertSeverity.WARNING,
                        "Unauthorized Page Integrity Modification",
                        f"HTML/DOM integrity hash changed unexpectedly on {url}.",
                        [diff_msg, f"Response time: {elapsed}ms"]
                    )
                # Update baseline
                target.baseline["body_hash"] = body_hash
                target.baseline["size_bytes"] = len(body)

        target.last_findings = findings if findings else [f"Verified clean. HTTP {status_code} ({elapsed}ms, {len(body)} bytes)"]
        if not is_hacked and target.status != TargetStatus.WARNING.value:
            target.status = TargetStatus.HEALTHY.value
            target.last_alert_title = ""

    async def _scan_huggingface(self, target: Target):
        repo_id = target.url_or_repo
        scan_res = await asyncio.to_thread(self.scanner.scan_repo, repo_id)

        if scan_res.scan_error:
            target.status = TargetStatus.DOWN.value
            target.last_findings = [scan_res.scan_error]
            self.emit_alert(
                target,
                AlertSeverity.HIGH,
                "Hugging Face Repository Inaccessible",
                f"Repository {repo_id} returned error during monitoring.",
                [scan_res.scan_error]
            )
            return

        current_commit = scan_res.metadata.get("last_modified", "")
        findings = []

        # Check baseline for unexpected commit modifications
        if "last_modified" not in target.baseline:
            target.baseline["last_modified"] = current_commit
            target.baseline["risk_score"] = scan_res.risk_score
            findings.append(f"Baseline initialized. Risk score: {scan_res.risk_score}/100")
        else:
            prev_commit = target.baseline.get("last_modified")
            if current_commit and current_commit != prev_commit:
                findings.append(f"New commit / modification detected at {current_commit}")
                self.emit_alert(
                    target,
                    AlertSeverity.WARNING,
                    "New Commit / Model Weights Updated",
                    f"Repository {repo_id} was modified. Re-evaluating threat vectors.",
                    [f"Previous: {prev_commit}", f"Current: {current_commit}"]
                )
                target.baseline["last_modified"] = current_commit

        # Evaluate scanner threats
        critical_threats = [t for t in scan_res.threats if t.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_threats:
            for t in critical_threats:
                findings.append(f"[{t.severity.value}] {t.title}: {t.description[:80]}...")
                self.emit_alert(
                    target,
                    AlertSeverity.CRITICAL if t.severity == Severity.CRITICAL else AlertSeverity.HIGH,
                    f"Model Tampering / Exploit: {t.title}",
                    t.description,
                    t.evidence
                )
            target.status = TargetStatus.COMPROMISED.value
        else:
            target.status = TargetStatus.HEALTHY.value
            findings.append(f"No critical exploit vectors found. {len(scan_res.files_scanned)} files audited.")

        target.last_findings = findings

    def simulate_attack(self, target_id: str) -> Optional[Alert]:
        """Simulates an active intrusion/defacement to test the alerting pipeline."""
        target = self.targets.get(target_id)
        if not target:
            return None

        alert = self.emit_alert(
            target,
            AlertSeverity.CRITICAL,
            "SIMULATED ATTACK: Web Shell / Pickle Exploit Injected",
            f"Intrusion detection triggered on {target.name}! Detected unauthorized webshell eval(base64_decode(...)) & reverse shell backdoor.",
            [
                "Payload: eval(base64_decode('c3lzdGVtKCJuYyAtZSAvYmluL3NoIDguOC44LjggNDQ0NCIpOw=='))",
                "Integrity Breach: SHA-256 hash checksum mismatch",
                "Action Taken: Webhook dispatched & administrative alert triggered"
            ]
        )
        return alert

# Global singleton
monitor_engine = ContinuousMonitoringEngine()
