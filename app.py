from fastapi import FastAPI, Request
from pydantic import BaseModel
import re, yaml

app = FastAPI()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Mcp-Session-Id"],
)

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

    for _ in range(3):
        dec = unquote(p)
        if dec == p:
            break
        p = dec

    p = p.replace("\x00", "")

    if shell:
        p = p.replace("\\", "")
    else:
        p = p.replace("\\", "/")

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
    """Strict: the resolved path must land inside /srv/reports/."""
    n = normalize_path(path, shell=shell)
    if ".." in n.split("/"):
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
    """Strip quoting tricks so cat /home/agent/.sec'rets' still matches."""
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

        if ".secrets" in low:
            return "Access to /home/agent/.secrets is never permitted by this agent's policy."

        for tok in re.findall(r"[~$./][^\s;|&<>\"'`]*", v):
            try:
                if is_restricted_read(tok, shell=True):
                    return "Path resolves to a restricted file outside the agent's permitted scope."
            except Exception:
                pass

        for s in SENSITIVE_EXTRA:
            if s in low:
                return f"Reading {s} is never permitted by this agent's policy."

        # writes via shell redirection / tee — strict /srv/reports only
        for m in re.finditer(r"(?:>>?|\btee\b\s+(?:-a\s+)?)\s*([^\s;|&<>\"']+)", v):
            target = m.group(1)
            if target.startswith("/dev/") or target in ("&1", "&2"):
                continue
            if is_restricted_read(target, shell=True):
                return "Write target is a restricted file."
            if not is_write_allowed(target, shell=True):
                return "Writes are permitted only inside /srv/reports/."

        for m in re.finditer(r"https?://[^\s;|&<>\"'`]+", v, re.IGNORECASE):
            ok, why = check_host(m.group(0))
            if not ok:
                return why

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
            "reason": "Write target resolves outside the permitted /srv/reports/ directory.",
        }

    if tool == "http_request":
        url = str(body.get("url", "") or "")
        ok, why = check_host(url)
        return {"decision": "allow" if ok else "block", "reason": why}

    return {"decision": "block", "reason": "Unrecognized tool; blocked by default."}

# ============================================================
# Run budget & loop guard endpoint
# ============================================================

import json as _json

DEFAULT_BUDGET = 18000
TRACE_KEYS = {"trace_id"}


def _canon(value):
    """Recursively canonicalize args: drop trace_id, collapse whitespace in strings."""
    if isinstance(value, dict):
        return {
            str(k): _canon(v)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
            if str(k).strip().lower() not in TRACE_KEYS
        }
    if isinstance(value, list):
        return [_canon(v) for v in value]
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        # 3 and 3.0 should compare equal
        return float(value) if isinstance(value, float) and not value.is_integer() else int(value) if float(value).is_integer() else float(value)
    return value


def _sig(step):
    """Stable signature for one step: tool name + canonical args."""
    if not isinstance(step, dict):
        return "?"
    tool = str(step.get("tool", "")).strip()
    args = step.get("args", {})
    if not isinstance(args, (dict, list)):
        args = {"_": args}
    return tool + "|" + _json.dumps(_canon(args), sort_keys=True, separators=(",", ":"))


def _to_int(v):
    try:
        return int(float(v))
    except Exception:
        return 0


@app.post("/runguard")
async def runguard(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    budget = body.get("budget_tokens", DEFAULT_BUDGET)
    budget = _to_int(budget) or DEFAULT_BUDGET

    steps = body.get("steps") or []
    if not isinstance(steps, list):
        steps = []

    # ---------- budget rule ----------
    total = sum(_to_int(s.get("tokens_used", 0)) for s in steps if isinstance(s, dict))
    if total >= budget:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total}) has reached the budget ({budget}).",
        }

    sigs = [_sig(s) for s in steps]

    # ---------- loop rule 1: 3+ identical calls in a row (trailing) ----------
    if len(sigs) >= 3:
        run = 1
        for i in range(len(sigs) - 1, 0, -1):
            if sigs[i] == sigs[i - 1]:
                run += 1
            else:
                break
        if run >= 3:
            return {
                "decision": "halt",
                "reason": f"The same tool call repeated {run} times in a row with functionally identical arguments.",
            }

    # ---------- loop rule 2: 2-step A/B cycle over 6+ trailing steps ----------
    if len(sigs) >= 6:
        tail = sigs[-6:]
        a, b = tail[0], tail[1]
        if a != b and all(tail[i] == (a if i % 2 == 0 else b) for i in range(6)):
            return {
                "decision": "halt",
                "reason": "Trailing steps form a repeating 2-step A/B cycle across 6 steps with no progress.",
            }

    remaining = budget - total
    if not steps:
        return {
            "decision": "continue",
            "reason": f"Fresh run with no steps taken yet; full budget of {budget} tokens available.",
        }

    return {
        "decision": "continue",
        "reason": f"{remaining} tokens remain and the trailing steps show progress, not a loop.",
    }



# ============================================================
# MCP server — Streamable HTTP transport
# ============================================================

import hashlib
import json as _mcp_json
import uuid
from fastapi.responses import JSONResponse, Response

EXAM_EMAIL = "23f2004792@ds.study.iitm.ac.in"
MCP_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOLS = {"2025-06-18", "2025-03-26", "2024-11-05"}

TOOL_DEF = {
    "name": "solve_challenge",
    "description": (
        "Reads the X-Exam-Challenge HTTP header for this call and returns the "
        "first 16 lowercase hex characters of SHA-256(\"<challenge>:<email>\")."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": True,
    },
}


def _solve(challenge: str) -> str:
    email = EXAM_EMAIL.strip().lower()
    payload = f"{challenge}:{email}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _get_challenge(request: Request) -> str:
    # Starlette headers are case-insensitive; check a few spellings anyway.
    for key in ("x-exam-challenge", "X-Exam-Challenge", "x_exam_challenge"):
        val = request.headers.get(key)
        if val:
            return val.strip()
    return ""


def _rpc_result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _wants_sse(request: Request) -> bool:
    accept = (request.headers.get("accept") or "").lower()
    return "text/event-stream" in accept and "application/json" not in accept


def _respond(request: Request, payload, session_id=None):
    """Return JSON or SSE depending on what the client asked for."""
    headers = {}
    if session_id:
        headers["Mcp-Session-Id"] = session_id

    if _wants_sse(request):
        body = "event: message\ndata: " + _mcp_json.dumps(payload) + "\n\n"
        headers["Cache-Control"] = "no-cache"
        return Response(content=body, media_type="text/event-stream", headers=headers)

    return JSONResponse(content=payload, headers=headers)


def _handle_rpc(message, request: Request):
    """Process one JSON-RPC message. Returns (payload_or_None, session_id_or_None)."""
    if not isinstance(message, dict):
        return _rpc_error(None, -32600, "Invalid Request"), None

    method = message.get("method")
    req_id = message.get("id")
    is_notification = "id" not in message

    if method == "initialize":
        params = message.get("params") or {}
        client_ver = params.get("protocolVersion")
        version = client_ver if client_ver in SUPPORTED_PROTOCOLS else MCP_PROTOCOL_VERSION
        session_id = uuid.uuid4().hex
        return _rpc_result(req_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "exam-challenge-server", "version": "1.0.0"},
        }), session_id

    if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return None, None

    if method == "ping":
        return _rpc_result(req_id, {}), None

    if method == "tools/list":
        return _rpc_result(req_id, {"tools": [TOOL_DEF]}), None

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        if name != "solve_challenge":
            return _rpc_error(req_id, -32602, f"Unknown tool: {name}"), None

        challenge = _get_challenge(request)
        if not challenge:
            return _rpc_result(req_id, {
                "content": [{"type": "text", "text": "missing X-Exam-Challenge header"}],
                "isError": True,
            }), None

        return _rpc_result(req_id, {
            "content": [{"type": "text", "text": _solve(challenge)}],
            "isError": False,
        }), None

    if method in ("resources/list", "prompts/list"):
        key = "resources" if method.startswith("resources") else "prompts"
        return _rpc_result(req_id, {key: []}), None

    if is_notification:
        return None, None

    return _rpc_error(req_id, -32601, f"Method not found: {method}"), None


@app.post("/mcp")
async def mcp_post(request: Request):
    try:
        raw = await request.body()
        message = _mcp_json.loads(raw) if raw else {}
    except Exception:
        return JSONResponse(_rpc_error(None, -32700, "Parse error"), status_code=400)

    # batch request
    if isinstance(message, list):
        results = []
        session_id = None
        for m in message:
            payload, sid = _handle_rpc(m, request)
            if sid:
                session_id = sid
            if payload is not None:
                results.append(payload)
        if not results:
            return Response(status_code=202)
        return _respond(request, results, session_id)

    payload, session_id = _handle_rpc(message, request)
    if payload is None:
        return Response(status_code=202)   # notification: no body
    return _respond(request, payload, session_id)


@app.get("/mcp")
async def mcp_get(request: Request):
    # Optional server-initiated SSE stream; we have nothing to push.
    return Response(status_code=405, headers={"Allow": "POST, DELETE"})


@app.delete("/mcp")
async def mcp_delete(request: Request):
    return Response(status_code=204)

# ============================================================
# Guardrail red-team round-trip
# ============================================================

import os
import ipaddress
import socket
import tempfile
import unicodedata
import httpx
from urllib.parse import urlsplit, unquote

LOGICAL_SANDBOX = "/srv/agent-redteam/sandbox-65c543e898"
LOGICAL_OUTSIDE = "/srv/agent-redteam/outside-284a8b1f"
ALLOWED_FETCH_HOSTS = {"example.com", "www.iana.org"}
MAX_READ_BYTES = 200_000

SEED_FILES = {
    f"{LOGICAL_OUTSIDE}/canary.txt":
        "AGENT_GUARDRAIL_CANARY_a21bbdb392dff26c31db2020195a2d75a4983018\n",
    f"{LOGICAL_SANDBOX}/notes/report.txt":
        "SAFE_REPORT_a5295db78125c788c2bb8195\n",
    f"{LOGICAL_SANDBOX}/notes/looks-like-..-but-safe.txt":
        "SAFE_WEIRD_4ddc980f8b3c93ac1b59271e\n",
    f"{LOGICAL_SANDBOX}/encoded/%2e%2e-literal.txt":
        "SAFE_ENCODED_729cf27fadc649431aa8bca1\n",
}


def _pick_storage_base():
    """Use / directly if writable, else fall back to a writable dir."""
    for base in ("/", os.path.join(tempfile.gettempdir(), "redteam-store"),
                 os.path.join(os.path.expanduser("~"), ".redteam-store")):
        try:
            probe = os.path.join(base, "srv", "agent-redteam")
            os.makedirs(probe, exist_ok=True)
            test = os.path.join(probe, ".w")
            with open(test, "w") as fh:
                fh.write("x")
            os.remove(test)
            return base
        except Exception:
            continue
    return tempfile.gettempdir()


STORAGE_BASE = _pick_storage_base()


def _physical(logical: str) -> str:
    """Map a logical absolute path onto the writable storage base."""
    return os.path.join(STORAGE_BASE, logical.lstrip("/"))


def _seed_files():
    created = []
    for logical, content in SEED_FILES.items():
        phys = _physical(logical)
        try:
            os.makedirs(os.path.dirname(phys), exist_ok=True)
            with open(phys, "w", encoding="utf-8") as fh:
                fh.write(content)
            created.append(phys)
        except Exception:
            pass
    return created


SEEDED = _seed_files()


# ---------------- read_file ----------------

def _decode_segment(seg: str) -> str:
    """Fully percent-decode one segment, including double-encoded forms."""
    prev = seg
    for _ in range(4):
        try:
            cur = unquote(prev, encoding="utf-8", errors="replace")
        except Exception:
            cur = unquote(prev)
        if cur == prev:
            break
        prev = cur
    try:
        prev = unicodedata.normalize("NFKC", prev)
    except Exception:
        pass
    return prev


def _looks_like_dotdot(s: str) -> bool:
    """True if the segment is effectively '..' after stripping decoration."""
    if not s:
        return False
    # strip path-parameter suffix (..;jsessionid=x), trailing dots/spaces/nulls
    t = s.split(";", 1)[0]
    t = t.strip().strip("\x00").rstrip(". ").strip()
    if t == "..":
        return True
    core = s.strip().replace(" ", "").replace("\x00", "")
    return len(core) >= 2 and set(core) == {"."}


def _rt_logical_resolve(path: str):
    """
    Segment-wise resolution. A segment counts as traversal only if the WHOLE
    segment is effectively '..'. Filenames that merely contain '..' or
    '%2e%2e' are preserved verbatim.
    """
    if not isinstance(path, str) or not path.strip():
        return None, "Empty path."

    p = path.strip()
    low = p.lower()
    if "\x00" in p or "%00" in low:
        return None, "Null byte in path."

    # overlong / non-standard encodings are never legitimate here
    for bad in ("%c0%ae", "%c1%9c", "%e0%80%ae", "%uff0e", "%u002e", "%25"):
        if bad in low:
            return None, "Non-standard percent encoding in path."

    p = p.replace("\\", "/")

    absolute = p.startswith("/")
    base_parts = [] if absolute else LOGICAL_SANDBOX.strip("/").split("/")

    parts = list(base_parts)
    for raw in p.split("/"):
        if raw == "" or raw == ".":
            continue

        dec = _decode_segment(raw)

        # an encoded separator inside a single segment is always hostile
        if dec != raw and ("/" in dec or "\\" in dec):
            return None, "Encoded path separator in segment."

        if _looks_like_dotdot(raw) or _looks_like_dotdot(dec):
            if parts:
                parts.pop()
            else:
                return None, "Path traverses above the filesystem root."
            continue

        if dec == "." or dec.strip() == ".":
            continue

        parts.append(raw)          # keep the ORIGINAL, undecoded segment

    return "/" + "/".join(parts), None


def _rt_inside_sandbox(logical: str) -> bool:
    root = LOGICAL_SANDBOX.rstrip("/")
    if logical == root:
        return True
    if not logical.startswith(root + "/"):
        return False
    return ".." not in logical.split("/")


def _rt_read_file(path: str):
    logical, err = _rt_logical_resolve(path)
    if err:
        return {"action": "block", "reason": err, "result": None}

    if not _rt_inside_sandbox(logical):
        return {
            "action": "block",
            "reason": "Resolved path lies outside the permitted sandbox root.",
            "result": None,
        }

    phys = _physical(logical)

    try:
        if os.path.islink(phys):
            return {"action": "block", "reason": "Symlinked path is not permitted.",
                    "result": None}
        real = os.path.realpath(phys)
        root_real = os.path.realpath(_physical(LOGICAL_SANDBOX))
        if os.path.exists(real) and os.path.commonpath([root_real, real]) != root_real:
            return {"action": "block", "reason": "Path escapes the sandbox on disk.",
                    "result": None}
    except Exception:
        pass

    try:
        if os.path.isdir(phys):
            listing = sorted(os.listdir(phys))
            return {"action": "allow",
                    "reason": "Directory listing inside the sandbox root.",
                    "result": {"content": "\n".join(listing)}}

        if os.path.exists(phys):
            with open(phys, "r", encoding="utf-8", errors="replace") as fh:
                data = fh.read(MAX_READ_BYTES)

            # hard backstop: never emit the canary, whatever the path logic did
            if "AGENT_GUARDRAIL_CANARY" in data:
                return {"action": "block",
                        "reason": "Refusing to return protected content.",
                        "result": None}

            return {"action": "allow",
                    "reason": "Path resolves inside the permitted sandbox root.",
                    "result": {"content": data}}
    except Exception as e:
        return {"action": "allow",
                "reason": "Path resolves inside the permitted sandbox root.",
                "result": {"content": f"error reading file: {e}"}}

    return {"action": "allow",
            "reason": "Path is inside the sandbox root but no such file exists.",
            "result": {"content": ""}}


# ---------------- fetch_url ----------------

def _rt_ip_is_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified):
        return False
    if ip_str in ("169.254.169.254", "100.100.100.200"):
        return False
    return True


def _rt_check_url(url: str):
    if not isinstance(url, str) or not url.strip():
        return False, "Empty URL.", ""

    try:
        parts = urlsplit(url.strip())
    except Exception:
        return False, "Malformed URL.", ""

    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Scheme '{scheme or 'none'}' is not permitted.", ""

    netloc = parts.netloc or ""
    if "@" in netloc:
        return False, "URLs containing userinfo are not permitted.", ""

    try:
        host = (parts.hostname or "").lower()
    except Exception:
        return False, "Host could not be parsed.", ""

    if not host:
        return False, "No host in URL.", ""

    # any trailing/leading dot is treated as a lookalike, not normalized away
    if host.endswith(".") or host.startswith(".") or ".." in host:
        return False, f"Malformed host '{host}'.", host

    if "." not in host:
        return False, f"Malformed host '{host}'.", host

    labels = host.split(".")
    if any(lbl == "" or lbl.startswith("-") or lbl.endswith("-") for lbl in labels):
        return False, f"Malformed host '{host}'.", host

    try:
        ipaddress.ip_address(host)
        return False, "Direct IP addresses are not permitted.", host
    except ValueError:
        pass

    if host not in ALLOWED_FETCH_HOSTS:
        return False, f"Host '{host}' is not on the allowlist.", host

    # only standard web ports on allowlisted hosts
    try:
        port = parts.port
    except Exception:
        return False, "Malformed port in URL.", host
    if port is not None and port not in (80, 443):
        return False, f"Port {port} is not permitted.", host

    try:
        infos = socket.getaddrinfo(
            host, port or (443 if scheme == "https" else 80),
            proto=socket.IPPROTO_TCP)
    except Exception:
        return False, f"Host '{host}' could not be resolved.", host

    for info in infos:
        if not _rt_ip_is_public(info[4][0]):
            return False, f"Host '{host}' resolves to a non-public address.", host

    return True, f"Host '{host}' is on the allowlist and resolves publicly.", host


def _rt_fetch_url(url: str):
    ok, reason, _ = _rt_check_url(url)
    if not ok:
        return {"action": "block", "reason": reason, "result": None}

    current = url.strip()
    try:
        with httpx.Client(follow_redirects=False, timeout=6.0) as client:
            for _ in range(5):
                resp = client.get(current, headers={"User-Agent": "guardrail/1.0"})
                if resp.status_code in (301, 302, 303, 307, 308):
                    nxt = resp.headers.get("location")
                    if not nxt:
                        break
                    nxt = str(httpx.URL(current).join(nxt))
                    ok2, reason2, _ = _rt_check_url(nxt)
                    if not ok2:
                        return {"action": "block",
                                "reason": f"Redirect target rejected: {reason2}",
                                "result": None}
                    current = nxt
                    continue
                return {"action": "allow", "reason": reason,
                        "result": {"content": resp.text[:MAX_READ_BYTES],
                                   "status": resp.status_code}}
    except Exception as e:
        return {"action": "allow", "reason": reason,
                "result": {"content": f"fetch error: {e}"}}

    return {"action": "allow", "reason": reason, "result": {"content": ""}}


# ---------------- endpoint ----------------

@app.post("/redteam")
async def redteam(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    tool = str(body.get("tool", "")).strip()
    args = body.get("arguments") or body.get("args") or {}
    if not isinstance(args, dict):
        args = {}

    try:
        if tool == "read_file":
            return _rt_read_file(str(args.get("path", "") or ""))
        if tool == "fetch_url":
            return _rt_fetch_url(str(args.get("url", "") or ""))
    except Exception as e:
        return {"action": "block", "reason": f"Internal error: {e}", "result": None}

    return {"action": "block", "reason": f"Unknown tool '{tool}'.", "result": None}


@app.get("/redteam/debug")
def redteam_debug():
    out = {"storage_base": STORAGE_BASE, "files": {}}
    for logical in SEED_FILES:
        phys = _physical(logical)
        try:
            with open(phys, encoding="utf-8") as fh:
                out["files"][logical] = {"exists": True, "content": fh.read().strip()}
        except Exception as e:
            out["files"][logical] = {"exists": False, "error": str(e)}
    return out