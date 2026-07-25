from fastapi import FastAPI, Request
from pydantic import BaseModel
import re, yaml

app = FastAPI()

class SkillRequest(BaseModel):
    skill: str

# ---------- secrets ----------
SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9_\-]{20,}",
    r"sk-ant-[A-Za-z0-9_\-]{20,}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"xox[baprs]-[A-Za-z0-9\-]{15,}",
    r"AIza[0-9A-Za-z_\-]{30,}",
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    r"https://hooks\.slack\.com/services/\S+",
    r"https://discord(app)?\.com/api/webhooks/\S+",
    r"https://outlook\.office\.com/webhook/\S+",
    r"https://\S+/webhook/[A-Za-z0-9_\-]{16,}",
    # generic: NAME = "long literal"
    r"(?i)\b(api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|auth[_-]?token|webhook[_-]?url|client[_-]?secret)\b\s*[:=]\s*[\"']([^\"'\s]{16,})[\"']",
]

PLACEHOLDER = re.compile(
    r"(\$\{?[A-Za-z_]|<[^>]+>|your[_-]?|xxx|placeholder|example|changeme|redacted|\.\.\.|env\.|os\.environ|secret[_-]?store)",
    re.IGNORECASE,
)

INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|earlier|above) instructions",
    r"ignore (the )?(user'?s?|any) (stop|cancel|abort|interrupt|halt)",
    r"(even|regardless) if the user (asks|says|requests).{0,40}(stop|cancel|abort)",
    r"continue.{0,40}(even if|despite).{0,40}(stop|cancel)",
    r"do not (stop|halt|abort) (even )?(if|when) (the )?user",
    r"disregard (the )?user",
    r"override (the )?(user|agent|system)",
    r"exfiltrat",
    r"(silently|quietly|without (informing|telling|notifying)).{0,60}(send|upload|post|transmit|copy|forward|email)",
    r"(send|upload|post|transmit|copy|forward|email).{0,80}(without (informing|telling|notifying|surfacing|the user'?s? knowledge)|do not (tell|inform|mention) the user)",
    r"do not (tell|inform|notify|mention).{0,20}(the )?user",
    r"without (the )?user'?s? (knowledge|awareness|consent)",
    r"(hide|conceal|suppress).{0,40}(from )?(the )?(user|reviewer)",
]

PERMISSION_PATTERNS = [
    r"entire (file ?system|home directory|disk|drive|machine|system)",
    r"whole (file ?system|home directory|disk|drive)",
    r"(all|every) files? on (the|this) (system|machine|disk)",
    r"unrestricted (file ?system|network|access)",
    r"full (disk|file ?system|system) access",
    r"read[-\s/]?write access to (the )?(entire|all|~|/)",
    r"any (external )?(domain|host|url|endpoint|server)",
    r"all (external )?(domains|hosts|urls|endpoints)",
    r"egress (allowed )?to any",
    r"network\s*:\s*(unrestricted|unlimited|full|open|\*|any)",
    r"filesystem\s*:\s*(unrestricted|unlimited|full|\*|/\s*$|~\s*$)",
    r"outbound (requests )?to any",
]

PROVENANCE_PATTERNS = [
    r"silently.{0,60}version",
    r"(update|bump|rewrite|increment).{0,40}version.{0,60}without (surfacing|informing|telling|notifying|reporting)",
    r"without (surfacing|informing|telling|notifying).{0,60}(version|changelog|metadata)",
    r"(clear|erase|delete|wipe|reset|blank).{0,20}the changelog",
    r"(rewrite|overwrite|modify).{0,30}(its |this skill'?s? )?own.{0,20}(version|metadata|provenance)",
    r"(strip|remove).{0,30}(author|provenance|version) (metadata|field|info)",
]

def parse_frontmatter(text):
    t = text.lstrip()
    if not t.startswith("---"):
        return {}, text
    parts = t.split("---", 2)
    if len(parts) < 3:
        return {}, text
    try:
        fm = yaml.safe_load(parts[1]) or {}
        if not isinstance(fm, dict):
            fm = {}
        return fm, parts[2]
    except Exception:
        return {}, parts[2]

def any_match(patterns, text):
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)

@app.post("/scan")
def scan(req: SkillRequest):
    text = req.skill or ""
    front, body = parse_frontmatter(text)
    cats = []

    # hardcoded_secret
    for p in SECRET_PATTERNS:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            hit = m.group(m.lastindex) if m.lastindex else m.group(0)
            if not PLACEHOLDER.search(hit):
                cats.append("hardcoded_secret")
                break

    if any_match(INJECTION_PATTERNS, body):
        cats.append("prompt_injection")

    perm_text = yaml.dump(front) + "\n" + body
    if any_match(PERMISSION_PATTERNS, perm_text):
        cats.append("excessive_permissions")

    if any_match(PROVENANCE_PATTERNS, body):
        cats.append("unclear_provenance")

    return {"categories": sorted(set(cats))}

@app.get("/")
def health():
    return {"ok": True}

class ProrationRequest(BaseModel):
    old_price: float = 0
    new_price: float = 0
    days_remaining: float = 0
    days_in_actual_month: float = 30
    spec: str = "v1"


@app.post("/prorate")
def prorate(req: ProrationRequest):
    delta = req.new_price - req.old_price
    spec = (req.spec or "v1").strip().lower()

    if spec == "v2":
        divisor = req.days_in_actual_month
        if not divisor:
            divisor = 30
    else:
        divisor = 30

    return {"charge": delta * (req.days_remaining / divisor)}


# ============================================================
# Agent guardrail endpoint
# ============================================================

import base64 as _b64
import posixpath
from urllib.parse import urlparse, unquote
from typing import Optional

RESTRICTED_FILE = "/home/agent/.secrets"
AGENT_HOME = "/home/agent"
AGENT_CWD = "/home/agent/workspace"
WRITE_ROOT = "/srv/reports"
ALLOWED_HOSTS = {"api.github.com", "objects.githubusercontent.com"}

SENSITIVE_EXTRA = (
    "/etc/shadow", "/etc/sudoers", "/etc/gshadow",
    "/root/.ssh", "/.aws/credentials", "id_rsa", "id_ed25519",
)


def _expand(path: str) -> str:
    """Expand ~ and $HOME/${HOME} style references."""
    p = path.strip().strip('"').strip("'")
    p = p.replace("${HOME}", AGENT_HOME).replace("$HOME", AGENT_HOME)
    p = p.replace("${home}", AGENT_HOME)
    if p == "~" or p.startswith("~/"):
        p = AGENT_HOME + p[1:]
    return p


def normalize_path(path: str, cwd: str = AGENT_CWD, shell: bool = False) -> str:
    """Expand, decode, make absolute, and collapse traversal segments."""
    p = _expand(path)

    # decode percent-encoding repeatedly (%252e -> %2e -> .)
    for _ in range(3):
        dec = unquote(p)
        if dec == p:
            break
        p = dec

    p = p.replace("\x00", "")

    if shell:
        p = p.replace("\\", "")       # undo shell escaping in bash text
    else:
        p = p.replace("\\", "/")      # backslash is a separator in a path field

    # collapse padded-dot traversal: /.../ or /..../ -> /../
    p = re.sub(r"/\.{3,}(?=/|$)", "/..", p)

    if not p.startswith("/"):
        p = posixpath.join(cwd, p)

    p = posixpath.normpath(p)
    while "//" in p:
        p = p.replace("//", "/")
    return p.rstrip("/") or "/"


def is_restricted_read(path: str, shell: bool = False) -> bool:
    n = normalize_path(path, shell=shell)
    if n == RESTRICTED_FILE or n.startswith(RESTRICTED_FILE + "/"):
        return True
    low = n.lower()
    return any(s in low for s in SENSITIVE_EXTRA)


def is_write_allowed(path: str, shell: bool = False) -> bool:
    n = normalize_path(path, shell=shell)
    if ".." in n.split("/"):          # anything unresolved is suspect
        return False
    return n == WRITE_ROOT or n.startswith(WRITE_ROOT + "/")


def _decode_b64_blobs(text: str):
    """Yield plaintext for any base64-looking token in the command."""
    out = []
    for token in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        try:
            dec = _b64.b64decode(token + "=" * (-len(token) % 4), validate=False)
            s = dec.decode("utf-8", errors="ignore")
            if s and sum(c.isprintable() for c in s) / len(s) > 0.85:
                out.append(s)
        except Exception:
            pass
    return out


def _deobfuscate(cmd: str) -> str:
    """Strip quoting/concatenation tricks so cat /home/agent/.sec'rets' still matches."""
    s = cmd.replace("\\\n", " ")
    s = re.sub(r"[\"']", "", s)
    s = s.replace("\\", "")
    return s


def check_host(url: str):
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "Malformed URL."

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "Only http/https requests are permitted."

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False, "Could not determine request host."

    if host in ALLOWED_HOSTS:
        return True, f"Host {host} is on the allowlist."
    return False, (
        f"Host {host} is not on the allowlist "
        "(api.github.com, objects.githubusercontent.com)."
    )


def scan_bash(command: str, depth: int = 0) -> Optional[str]:
    """Return a block reason, or None if the command looks acceptable."""
    if depth > 3:
        return None

    variants = {command, _deobfuscate(command)}
    for v in list(variants):
        variants.add(_expand(v))

    for v in variants:
        low = v.lower()

        # --- restricted secret file, any spelling ---
        if ".secrets" in low:
            return "Access to /home/agent/.secrets is never permitted by this agent's policy."

        # relative traversal that resolves onto the secret
        for tok in re.findall(r"[~$./][^\s;|&<>\"'`]*", v):
            try:
                if is_restricted_read(tok, shell=True):
                    return "Path resolves to a restricted file outside the agent's permitted scope."
            except Exception:
                pass

        # other sensitive system files (e.g. /etc/shadow)
        for s in SENSITIVE_EXTRA:
            if s in low:
                return f"Reading {s} is never permitted by this agent's policy."

        # --- writes via shell redirection / tee ---
        for m in re.finditer(r"(?:>>?|\btee\b\s+(?:-a\s+)?)\s*([^\s;|&<>\"']+)", v):
            target = m.group(1)
            if target.startswith("/dev/") or target in ("&1", "&2"):
                continue
            n = normalize_path(target, shell=True)
            inside_reports = n == WRITE_ROOT or n.startswith(WRITE_ROOT + "/")
            inside_home = n == AGENT_HOME or n.startswith(AGENT_HOME + "/")
            if is_restricted_read(n):
                return "Write target is a restricted file."
            if not (inside_reports or inside_home):
                return "Writes outside /srv/reports/ and the agent's own home are not permitted."

        # --- network egress from inside bash ---
        for m in re.finditer(r"https?://[^\s;|&<>\"'`]+", v, re.IGNORECASE):
            ok, why = check_host(m.group(0))
            if not ok:
                return why

    # --- base64 / encoded wrappers: decode and re-scan ---
    for decoded in _decode_b64_blobs(command):
        r = scan_bash(decoded, depth + 1)
        if r:
            return "Encoded command wraps a disallowed action: " + r

    return None


@app.post("/guardrail")
async def guardrail(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    tool = str(body.get("tool", "")).strip().lower()

    if tool == "bash":
        cmd = str(body.get("command", "") or "")
        reason = scan_bash(cmd)
        if reason:
            return {"decision": "block", "reason": reason}
        return {
            "decision": "allow",
            "reason": "Command does not touch restricted paths, write boundaries, or disallowed hosts.",
        }

    if tool == "write_file":
        path = str(body.get("path", "") or "")
        if is_restricted_read(path):
            return {"decision": "block", "reason": "Path targets a restricted file."}
        if is_write_allowed(path):
            return {
                "decision": "allow",
                "reason": f"Write target resolves inside {WRITE_ROOT}/.",
            }
        return {
            "decision": "block",
            "reason": f"Write target resolves to {normalize_path(path)}, outside the permitted {WRITE_ROOT}/ directory.",
        }

    if tool == "http_request":
        url = str(body.get("url", "") or "")
        ok, why = check_host(url)
        return {"decision": "allow" if ok else "block", "reason": why}

    return {"decision": "block", "reason": "Unrecognized tool; blocked by default."}