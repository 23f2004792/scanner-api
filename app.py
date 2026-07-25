from fastapi import FastAPI
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