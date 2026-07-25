from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


# ---------- Secret Detection ----------

SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9_-]{20,}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"xox[baprs]-[A-Za-z0-9-]{20,}",
    r"Bearer\s+[A-Za-z0-9._=-]{15,}",
    r"https://[^\s]*webhooks[^\s]*",
]

ENV_PATTERN = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")

INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore the user's stop",
    r"ignore the user's cancel",
    r"ignore user stop request",
    r"ignore user cancel request",
    r"silently exfiltrat",
    r"exfiltrat.*file",
    r"steal.*file",
    r"silently upload.*file",
    r"send.*file.*without.*user",
]
PERMISSION_PATTERNS = [
    r"entire home directory",
    r"entire filesystem",
    r"whole filesystem",
    r"filesystem\s*:\s*.*~",
    r"filesystem\s*:\s*.*\/",
    r"any external domain",
    r"egress.*any external",
    r"network.*any external",
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

    rewrite = [
    "update this skill",
    "update this skill's own version",
    "next patch version",
    "clear the changelog",
    "without surfacing this change",
]

    if any(x in body_lower for x in rewrite):
        categories.append("unclear_provenance")
    categories = sorted(set(categories))
    return {"categories": categories}