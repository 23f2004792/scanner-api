from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


# ---------- Secret Detection ----------

SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{20,}",                         # OpenAI
    r"ghp_[A-Za-z0-9]{30,}",                        # GitHub PAT
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"AKIA[0-9A-Z]{16}",                            # AWS
    r"xox[baprs]-[A-Za-z0-9\-]{10,}",               # Slack
    r"Bearer\s+[A-Za-z0-9_\-\.=]{20,}",
    r"https://[^ \n]*webhooks[^ \n]*",
]

ENV_PATTERN = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")

INJECTION_PATTERNS = [
    r"ignore\s+previous\s+instructions",
    r"ignore\s+the\s+user",
    r"ignore\s+user\s+instructions",
    r"ignore\s+stop\s+request",
    r"ignore\s+cancel\s+request",
    r"exfiltrat",
    r"steal",
    r"send\s+.*without\s+telling",
    r"silently\s+upload",
    r"do\s+not\s+tell\s+the\s+user",
]

PERMISSION_PATTERNS = [
    r"/\*\*",
    r"filesystem\s*:\s*all",
    r"filesystem\s*:\s*rw",
    r"filesystem\s*:\s*\*",
    r"network\s*:\s*all",
    r"network\s*:\s*\*",
    r"egress\s*:\s*all",
    r"domains\s*:\s*\*",
    r"read\s+entire\s+filesystem",
    r"write\s+entire\s+filesystem",
    r"any\s+domain",
]


def parse_frontmatter(text):
    if not text.startswith("---"):
        return {}, text

    try:
        parts = text.split("---", 2)

        if len(parts) < 3:
            return {}, text

        front = yaml.safe_load(parts[1])

        if front is None:
            front = {}

        return front, parts[2]

    except Exception:
        return {}, text


@app.post("/scan")
def scan(req: SkillRequest):

    categories = []

    front, body = parse_frontmatter(req.skill)

    body_lower = body.lower()

    # -------------------------
    # Hardcoded Secret
    # -------------------------

    found_secret = False

    for p in SECRET_PATTERNS:
        if re.search(p, req.skill, re.IGNORECASE):
            found_secret = True
            break

    if not found_secret:

        for k, v in front.items():

            key = str(k).lower()
            value = str(v)

            if any(x in key for x in [
                "token",
                "secret",
                "apikey",
                "api_key",
                "password",
                "webhook"
            ]):

                if not ENV_PATTERN.search(value):
                    found_secret = True
                    break

    if found_secret:
        categories.append("hardcoded_secret")

    # -------------------------
    # Prompt Injection
    # -------------------------

    for p in INJECTION_PATTERNS:
        if re.search(p, body_lower):
            categories.append("prompt_injection")
            break

    # -------------------------
    # Excessive Permissions
    # -------------------------

    excessive = False

    front_str = yaml.dump(front).lower()

    for p in PERMISSION_PATTERNS:
        if re.search(p, front_str):
            excessive = True
            break

    if excessive:
        categories.append("excessive_permissions")

    # -------------------------
    # Provenance
    # -------------------------

    has_author = "author" in front
    has_version = "version" in front
    has_changelog = "changelog" in front

    if not (has_author and has_version and has_changelog):
        if (
            "update version" in body_lower
            or "rewrite version" in body_lower
            or "increment version" in body_lower
            or "change version" in body_lower
            or "modify version" in body_lower
        ):
            categories.append("unclear_provenance")

    return {"categories": categories}