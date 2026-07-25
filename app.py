from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml

app = FastAPI()

class SkillRequest(BaseModel):
    skill: str

@app.post("/scan")
def scan(req: SkillRequest):

    text = req.skill
    categories = []

    # ---------- Parse YAML ----------
    frontmatter = {}

    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            try:
                frontmatter = yaml.safe_load(parts[1]) or {}
            except:
                frontmatter = {}

    lower = text.lower()

    # ---------- Hardcoded Secret ----------
    secret_patterns = [
        r"sk-[a-zA-Z0-9]{10,}",
        r"api[_-]?key\s*[:=]",
        r"bearer\s+[a-zA-Z0-9_\-]{10,}",
        r"https://.*webhooks",
        r"secret\s*[:=]"
    ]

    for p in secret_patterns:
        if re.search(p, text, re.IGNORECASE):
            if "${" not in text:
                categories.append("hardcoded_secret")
                break

    # ---------- Prompt Injection ----------

    injection_words = [
        "ignore previous",
        "ignore the user",
        "ignore user",
        "silently",
        "without telling",
        "exfiltrate",
        "steal",
        "cancel request",
        "do not tell the user"
    ]

    if any(x in lower for x in injection_words):
        categories.append("prompt_injection")

    # ---------- Permissions ----------

    perms = str(frontmatter).lower()

    if (
        "/**" in perms
        or "*" in perms
        or "all files" in perms
        or "any domain" in perms
        or "write: true" in perms
    ):
        categories.append("excessive_permissions")

    # ---------- Provenance ----------

    if (
        "author" not in frontmatter
        or "version" not in frontmatter
        or "changelog" not in frontmatter
    ):
        categories.append("unclear_provenance")

    return {"categories": categories}