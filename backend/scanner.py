"""
HF Guardian - Advanced Hugging Face Security Scanner
Core scanning engine: analyzes repos for supply-chain threats.
"""

import re
import io
import sys
import json
import struct
import hashlib
import pickletools
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

# ─── Threat severity levels ────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Threat:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: list[str] = field(default_factory=list)
    mitigation: str = ""
    cve: Optional[str] = None


@dataclass
class ScanResult:
    repo_id: str
    threats: list[Threat] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    files_scanned: list[str] = field(default_factory=list)
    scan_error: Optional[str] = None
    risk_score: int = 0      # 0-100

    def compute_risk_score(self):
        score = 0
        weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 10, Severity.LOW: 5, Severity.INFO: 1}
        for t in self.threats:
            score += weights.get(t.severity, 0)
        self.risk_score = min(100, score)


# ─── Dangerous pickle opcodes / globals ───────────────────────────────────────

DANGEROUS_GLOBALS = {
    ("os",        "system"),
    ("os",        "popen"),
    ("subprocess","Popen"),
    ("subprocess","call"),
    ("subprocess","check_output"),
    ("subprocess","run"),
    ("builtins",  "eval"),
    ("builtins",  "exec"),
    ("builtins",  "compile"),
    ("builtins",  "__import__"),
    ("socket",    "socket"),
    ("ctypes",    "CDLL"),
    ("ctypes",    "cdll"),
    ("importlib", "import_module"),
    ("_posixsubprocess", "fork_exec"),
}

SUSPICIOUS_GLOBALS = {
    ("os",       "getenv"),
    ("os",       "environ"),
    ("os",       "listdir"),
    ("os",       "walk"),
    ("pathlib",  "Path"),
    ("shutil",   "copy"),
    ("tempfile", "NamedTemporaryFile"),
    ("urllib",   "request"),
    ("http",     "client"),
    ("socket",   "create_connection"),
    ("requests", "get"),
    ("requests", "post"),
}

# ─── Common legitimate pickle globals (allowlist) ─────────────────────────────

SAFE_ML_GLOBALS = {
    "torch", "collections", "numpy", "_codecs", "builtins.str", "builtins.int",
    "builtins.float", "builtins.list", "builtins.dict", "builtins.tuple",
    "builtins.set", "builtins.bytes", "builtins.bytearray", "OrderedDict",
}

# ─── Secrets regex patterns ────────────────────────────────────────────────────

SECRET_PATTERNS = [
    (re.compile(r'sk-[A-Za-z0-9]{48}'),                      "OpenAI API Key"),
    (re.compile(r'hf_[A-Za-z0-9]{37,}'),                     "Hugging Face Token"),
    (re.compile(r'AKIA[0-9A-Z]{16}'),                        "AWS Access Key"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                  "Google API Key"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'),                     "GitHub PAT"),
    (re.compile(r'xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}'), "Slack Bot Token"),
    (re.compile(r'(?i)password\s*[=:]\s*["\']?[A-Za-z0-9!@#$%^&*]{8,}'), "Hardcoded Password"),
    (re.compile(r'(?i)secret\s*[=:]\s*["\']?[A-Za-z0-9!@#$%^&*]{8,}'),   "Hardcoded Secret"),
    (re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),   "Private Key"),
]

# ─── Supply-chain suspicious patterns ─────────────────────────────────────────

TYPOSQUAT_TARGETS = ["openai", "mistral", "llama", "anthropic", "deepmind", "google",
                     "meta-llama", "stabilityai", "huggingface", "microsoft"]

SUSPICIOUS_REPO_PATTERNS = [
    re.compile(r'(?i)(free|crack|leak|pirat|warez|hack|keylog|stealer|ransomware)'),
    re.compile(r'(?i)(official|legit|real|genuine|original|authentic)\s*-?\s*(model|ai|gpt)'),
    re.compile(r'(?i)openai\s*[-_]?\s*official'),
    re.compile(r'(?i)chatgpt\s*[-_]?\s*v?\d'),
    re.compile(r'(?i)gpt[-_]?(5|4|o\d?|turbo|omni)[-_]?free'),
]


# ─── HF API helpers ────────────────────────────────────────────────────────────

HF_API = "https://huggingface.co/api"
HF_RAW = "https://huggingface.co"

def _get(url: str, timeout=10) -> dict | list | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HFGuardian/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None

def _get_bytes(url: str, max_bytes=2 * 1024 * 1024, timeout=15) -> bytes | None:
    """Download up to max_bytes from a URL."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HFGuardian/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes)
    except Exception:
        return None


# ─── Pickle scanner ───────────────────────────────────────────────────────────

class PickleScanner:
    """
    Static pickle opcode analyser — detects both standard malicious globals
    and Sleepy Pickle / Fickling-style in-memory payload injection.
    """

    PICKLE_MAGIC = b'\x80'  # protocol opcode prefix

    @staticmethod
    def is_pickle(data: bytes) -> bool:
        return data[:2] == b'\x80\x02' or data[:1] == b'\x80' or data[:1] == b'('

    @staticmethod
    def _pytorch_zip_pickles(data: bytes) -> list[bytes]:
        """Extract pickle streams from PyTorch .pt / .pth ZIP archives."""
        results = []
        PK = b'PK\x03\x04'
        offset = 0
        while True:
            idx = data.find(PK, offset)
            if idx == -1:
                break
            # read local file header
            try:
                name_len  = struct.unpack_from('<H', data, idx + 26)[0]
                extra_len = struct.unpack_from('<H', data, idx + 28)[0]
                file_data_offset = idx + 30 + name_len + extra_len
                comp_size = struct.unpack_from('<I', data, idx + 18)[0]
                fname = data[idx + 30: idx + 30 + name_len].decode(errors='replace')
                if fname.endswith('.pkl') or fname.endswith('.pickle') or 'data.pkl' in fname:
                    results.append(data[file_data_offset: file_data_offset + comp_size])
            except Exception:
                pass
            offset = idx + 1
        return results

    def scan(self, data: bytes, filename: str) -> list[Threat]:
        threats = []
        streams: list[tuple[str, bytes]] = []

        # Try PyTorch ZIP extraction first
        if data[:2] == b'PK':
            for i, pkl in enumerate(self._pytorch_zip_pickles(data)):
                streams.append((f"{filename}::data.pkl[{i}]", pkl))
        elif self.is_pickle(data):
            streams.append((filename, data))

        for stream_name, pkl_data in streams:
            t = self._analyse_stream(pkl_data, stream_name)
            threats.extend(t)

        return threats

    def _analyse_stream(self, data: bytes, name: str) -> list[Threat]:
        threats = []
        found_dangerous: set[tuple[str,str]] = set()
        found_suspicious: set[tuple[str,str]] = set()
        op_sequence: list[str] = []
        reduce_count = 0

        try:
            ops = list(pickletools.genops(data))
        except Exception as e:
            return [Threat(
                id="PICKLE_PARSE_ERROR",
                title="Pickle Parse Failure (Possible Obfuscation)",
                severity=Severity.HIGH,
                category="Pickle",
                description=f"Could not parse pickle stream in `{name}`. This may indicate intentional obfuscation to evade scanners.",
                evidence=[str(e)],
                mitigation="Do not load this file. Use safetensors format instead.",
            )]

        for opcode, arg, pos in ops:
            op_sequence.append(opcode.name)
            if opcode.name in ('GLOBAL', 'INST'):
                if isinstance(arg, str):
                    parts = arg.split(' ', 1)
                    if len(parts) == 2:
                        key = (parts[0], parts[1])
                        if key in DANGEROUS_GLOBALS:
                            found_dangerous.add(key)
                        elif key in SUSPICIOUS_GLOBALS:
                            found_suspicious.add(key)
            if opcode.name == 'REDUCE':
                reduce_count += 1

        # Sleepy Pickle heuristic: GLOBAL + REDUCE after weight tensors
        weight_ops = {'BINPUT', 'LONG_BINPUT', 'EMPTY_DICT', 'MARK', 'APPENDS'}
        has_weights = any(op in op_sequence for op in weight_ops)
        late_reduces = sum(1 for op in op_sequence[-20:] if op == 'REDUCE')

        if found_dangerous:
            evidence = [f"  • {mod}.{fn}()" for mod, fn in sorted(found_dangerous)]
            threats.append(Threat(
                id="PICKLE_DANGEROUS_GLOBAL",
                title="Malicious Code Execution via Pickle GLOBAL",
                severity=Severity.CRITICAL,
                category="Pickle / RCE",
                description=(
                    f"`{name}` calls dangerous Python globals during deserialization. "
                    "Loading this file will execute arbitrary code on your machine."
                ),
                evidence=evidence,
                mitigation="Delete this file immediately. Report the repository to Hugging Face. Use safetensors only.",
                cve="CVE-2019-20907 (pickle arbitrary code exec)",
            ))

        if has_weights and late_reduces >= 2 and not found_dangerous and found_suspicious:
            threats.append(Threat(
                id="SLEEPY_PICKLE",
                title="Sleepy Pickle / In-Memory Payload Injection Suspected",
                severity=Severity.CRITICAL,
                category="Sleepy Pickle",
                description=(
                    f"`{name}` contains model weights AND late-stage REDUCE operations that call "
                    "network/OS functions — the signature of a Sleepy Pickle attack. The payload runs "
                    "AFTER weights are loaded, evading naive scanners."
                ),
                evidence=[f"  • {mod}.{fn}" for mod, fn in sorted(found_suspicious)]
                        + [f"  • {late_reduces} REDUCE ops in final 20 opcodes"],
                mitigation="Do NOT load this file. Report to HF security team. Use fickling tool for forensics.",
                cve="Trail of Bits 2024 — Sleepy Pickle",
            ))
        elif found_suspicious:
            threats.append(Threat(
                id="PICKLE_SUSPICIOUS_GLOBAL",
                title="Suspicious Globals in Pickle Stream",
                severity=Severity.HIGH,
                category="Pickle",
                description=f"`{name}` references potentially dangerous modules that could exfiltrate data or make network calls.",
                evidence=[f"  • {mod}.{fn}" for mod, fn in sorted(found_suspicious)],
                mitigation="Inspect carefully. Prefer safetensors format.",
            ))

        if reduce_count > 50 and not found_dangerous:
            threats.append(Threat(
                id="PICKLE_EXCESSIVE_REDUCE",
                title="Unusually High REDUCE Count (Possible Evasion)",
                severity=Severity.MEDIUM,
                category="Pickle",
                description=f"`{name}` has {reduce_count} REDUCE opcodes. Evasion techniques sometimes use deeply-nested calls to hide payload globals.",
                evidence=[f"{reduce_count} REDUCE opcodes detected"],
                mitigation="Use fickling to decompile and inspect the full opcode stream.",
            ))

        return threats


# ─── Secret scanner ───────────────────────────────────────────────────────────

class SecretScanner:
    def scan_text(self, text: str, source: str) -> list[Threat]:
        threats = []
        for pattern, label in SECRET_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                # Redact found secrets in evidence
                redacted = [m[:6] + "..." + m[-4:] if len(m) > 12 else "***" for m in matches[:3]]
                threats.append(Threat(
                    id=f"SECRET_{label.upper().replace(' ', '_')}",
                    title=f"Leaked Secret: {label}",
                    severity=Severity.CRITICAL,
                    category="Credentials",
                    description=f"A {label} was found in `{source}`. This credential may be actively usable.",
                    evidence=redacted,
                    mitigation="Rotate the secret immediately. File a report with the hosting platform.",
                ))
        return threats


# ─── Metadata / supply-chain analyser ─────────────────────────────────────────

class MetadataAnalyser:
    def analyse(self, repo_id: str, meta: dict, model_info: dict) -> list[Threat]:
        threats = []
        author = repo_id.split('/')[0] if '/' in repo_id else repo_id
        name   = repo_id.split('/')[-1]

        # 1. Typosquatting check
        for target in TYPOSQUAT_TARGETS:
            if target != author.lower() and (
                self._levenshtein(author.lower(), target) <= 2
                or self._levenshtein(name.lower(), target) <= 2
            ):
                threats.append(Threat(
                    id="TYPOSQUAT",
                    title=f"Possible Typosquatting of '{target}'",
                    severity=Severity.HIGH,
                    category="Supply Chain",
                    description=f"The repository `{repo_id}` closely resembles the well-known entity `{target}`. This may be an impersonation attempt.",
                    evidence=[f"Author: {author}", f"Target: {target}", f"Edit distance: {self._levenshtein(author.lower(), target)}"],
                    mitigation="Verify the publisher is the official organization before loading.",
                ))

        # 2. Suspicious name patterns
        full_name = f"{author}/{name}"
        for pattern in SUSPICIOUS_REPO_PATTERNS:
            if pattern.search(full_name):
                threats.append(Threat(
                    id="SUSPICIOUS_NAME",
                    title="Suspicious Repository Name Pattern",
                    severity=Severity.HIGH,
                    category="Supply Chain",
                    description=f"The repository name `{full_name}` matches patterns associated with fake/malicious AI model releases.",
                    evidence=[f"Matched pattern: {pattern.pattern}", f"Full name: {full_name}"],
                    mitigation="Do not download. Check the model card and author profile carefully.",
                ))
                break

        # 3. Very new author with high download count (flash popularity = red flag)
        downloads = model_info.get("downloads", 0) or 0
        created_at = meta.get("created_at", "") or model_info.get("createdAt", "")
        if downloads > 50_000 and created_at:
            # rough days-old calculation from ISO date
            try:
                from datetime import datetime, timezone
                created = datetime.fromisoformat(created_at.replace("Z","")).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                age_days = (now - created).days
                if age_days < 14:
                    threats.append(Threat(
                        id="FLASH_POPULARITY",
                        title="Suspicious Flash Download Spike",
                        severity=Severity.HIGH,
                        category="Supply Chain",
                        description=(
                            f"This model has **{downloads:,} downloads** but was created only "
                            f"**{age_days} days ago**. A pattern seen in the 2026 fake OpenAI model campaign "
                            f"(244k downloads in days). Could be a botted supply-chain attack."
                        ),
                        evidence=[f"Downloads: {downloads:,}", f"Age: {age_days} days", f"Created: {created_at}"],
                        mitigation="Verify model authenticity independently before loading.",
                    ))
            except Exception:
                pass

        # 4. No model card / README
        has_readme = any(f.get("rfilename","").lower() in ("readme.md","model_card.md")
                        for f in model_info.get("siblings", []))
        if not has_readme:
            threats.append(Threat(
                id="NO_MODEL_CARD",
                title="Missing Model Card / README",
                severity=Severity.LOW,
                category="Transparency",
                description="Legitimate models almost always include a model card describing intended use, limitations, and training details. Absence is a red flag.",
                evidence=["No README.md or model_card.md found"],
                mitigation="Request documentation from the author or avoid use.",
            ))

        # 5. Unsafe file formats present
        files = [f.get("rfilename","") for f in model_info.get("siblings", [])]
        unsafe = [f for f in files if f.endswith(('.pkl','.pickle','.pt','.pth','.bin'))]
        safe   = [f for f in files if f.endswith('.safetensors')]
        if unsafe and not safe:
            threats.append(Threat(
                id="UNSAFE_FORMAT_ONLY",
                title="Only Unsafe Serialization Formats Present",
                severity=Severity.MEDIUM,
                category="File Format",
                description=f"This model only provides files in unsafe pickle-based formats with no safetensors alternative.",
                evidence=[f"Unsafe files: {', '.join(unsafe[:5])}"],
                mitigation="Ask the author to publish safetensors weights or convert yourself in a sandboxed environment.",
            ))
        elif unsafe:
            threats.append(Threat(
                id="MIXED_FORMATS",
                title="Unsafe Format Files Present Alongside Safetensors",
                severity=Severity.LOW,
                category="File Format",
                description="Safetensors files exist, but unsafe pickle-based files are also present. Load only the safetensors versions.",
                evidence=[f"Unsafe: {', '.join(unsafe[:5])}"],
                mitigation="Use safetensors files exclusively.",
            ))

        return threats

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if len(a) < len(b): a, b = b, a
        row = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            new_row = [i + 1]
            for j, cb in enumerate(b):
                new_row.append(min(row[j+1]+1, new_row[-1]+1, row[j]+(ca!=cb)))
            row = new_row
        return row[-1]


# ─── Config file scanner ───────────────────────────────────────────────────────

class ConfigScanner:
    """Scans config.json and tokenizer configs for embedded secrets or suspicious fields."""

    SUSPICIOUS_KEYS = {"auto_map", "custom_pipelines", "_commit_hash", "transformers_version"}

    def scan(self, config_text: str, filename: str) -> list[Threat]:
        threats = []
        secret_scanner = SecretScanner()
        threats.extend(secret_scanner.scan_text(config_text, filename))

        try:
            cfg = json.loads(config_text)
        except Exception:
            return threats

        # auto_map with custom classes = possible RCE on model load
        if "auto_map" in cfg:
            auto_map = cfg["auto_map"]
            if isinstance(auto_map, dict):
                for k, v in auto_map.items():
                    if isinstance(v, str) and '--' in v:
                        threats.append(Threat(
                            id="AUTO_MAP_CUSTOM_CLASS",
                            title="auto_map Contains Custom Remote Class",
                            severity=Severity.HIGH,
                            category="Config / RCE",
                            description=(
                                f"`{filename}` uses `auto_map` to load a custom class `{v}`. "
                                "When you call `AutoModel.from_pretrained()` with `trust_remote_code=True`, "
                                "this executes arbitrary code from the repository."
                            ),
                            evidence=[f"auto_map.{k} = {v}"],
                            mitigation="Never use trust_remote_code=True on untrusted repos. Audit modeling_*.py files first.",
                        ))

        return threats


# ─── Main orchestrator ────────────────────────────────────────────────────────

class HFScanner:
    def __init__(self):
        self.pickle_scanner  = PickleScanner()
        self.secret_scanner  = SecretScanner()
        self.meta_analyser   = MetadataAnalyser()
        self.config_scanner  = ConfigScanner()

    def scan_repo(self, repo_id: str) -> ScanResult:
        result = ScanResult(repo_id=repo_id)

        # ── Fetch model info ──────────────────────────────────────────────────
        model_info = _get(f"{HF_API}/models/{repo_id}") or {}
        if not model_info:
            result.scan_error = f"Repository '{repo_id}' not found or inaccessible."
            return result

        result.metadata = {
            "author":      model_info.get("author", "unknown"),
            "created_at":  model_info.get("createdAt", ""),
            "last_modified": model_info.get("lastModified", ""),
            "downloads":   model_info.get("downloads", 0),
            "likes":       model_info.get("likes", 0),
            "tags":        model_info.get("tags", []),
            "pipeline_tag": model_info.get("pipeline_tag", ""),
            "private":     model_info.get("private", False),
        }

        # ── Metadata / supply chain analysis ─────────────────────────────────
        result.threats.extend(
            self.meta_analyser.analyse(repo_id, {}, model_info)
        )

        # ── File-level scans ──────────────────────────────────────────────────
        siblings = model_info.get("siblings", [])
        SCAN_EXTENSIONS = (
            '.pkl', '.pickle', '.pt', '.pth', '.bin',     # pickle-based
            'config.json', 'tokenizer_config.json',        # config
            'special_tokens_map.json', 'tokenizer.json',   # tokenizer
        )

        for sibling in siblings:
            fname = sibling.get("rfilename", "")
            if not fname:
                continue
            if not any(fname.endswith(ext) or fname == ext for ext in SCAN_EXTENSIONS):
                continue

            fsize = sibling.get("size", 0) or 0
            # Skip very large weight files (>200 MB) for bandwidth; scan configs & small pckls
            if fsize > 200 * 1024 * 1024 and fname.endswith(('.pt','.pth','.bin')):
                result.threats.append(Threat(
                    id=f"LARGE_BINARY_{fname}",
                    title=f"Large Binary File Not Scanned ({fname})",
                    severity=Severity.INFO,
                    category="Scan Limitation",
                    description=f"`{fname}` ({fsize//1024//1024} MB) exceeds the scan limit. Download and run picklescan + fickling locally.",
                    mitigation="Use `pip install picklescan fickling && picklescan <file>` locally.",
                ))
                continue

            url = f"{HF_RAW}/{repo_id}/resolve/main/{fname}"
            file_data = _get_bytes(url)
            if not file_data:
                continue

            result.files_scanned.append(fname)

            # Pickle / binary scan
            if fname.endswith(('.pkl','.pickle','.pt','.pth','.bin')):
                result.threats.extend(self.pickle_scanner.scan(file_data, fname))
                # Also scan for embedded secrets in binary (rough text extraction)
                text_layer = file_data.decode('utf-8', errors='replace')
                result.threats.extend(self.secret_scanner.scan_text(text_layer, fname))

            # Config/JSON scan
            elif fname.endswith('.json'):
                try:
                    text = file_data.decode('utf-8', errors='replace')
                    result.threats.extend(self.config_scanner.scan(text, fname))
                except Exception:
                    pass

        # ── Python source files (modeling_*.py, *.py) ─────────────────────────
        py_files = [s.get("rfilename","") for s in siblings if s.get("rfilename","").endswith('.py')]
        for pyf in py_files[:5]:  # limit to first 5
            url = f"{HF_RAW}/{repo_id}/resolve/main/{pyf}"
            data = _get_bytes(url, max_bytes=512*1024)
            if not data:
                continue
            text = data.decode('utf-8', errors='replace')
            result.files_scanned.append(pyf)
            result.threats.extend(self.secret_scanner.scan_text(text, pyf))

            # Detect eval/exec patterns in modeling code
            for danger in ['eval(', 'exec(', '__import__(', 'subprocess.', 'os.system(']:
                if danger in text:
                    result.threats.append(Threat(
                        id=f"PYTHON_DANGER_{pyf}",
                        title=f"Dangerous Python in `{pyf}`",
                        severity=Severity.HIGH,
                        category="Code Injection",
                        description=f"`{pyf}` contains `{danger}` which executes when loaded with `trust_remote_code=True`.",
                        evidence=[f"Found: {danger}"],
                        mitigation="Audit the file fully before using trust_remote_code=True.",
                    ))
                    break

        result.compute_risk_score()
        return result
