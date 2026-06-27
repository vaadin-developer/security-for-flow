#!/usr/bin/env python3
"""
Download all jSentinel-SecurityFramework tasks from ClickUp back to local Markdown.

Reads CLICKUP_TOKEN from environment. Recreates the layout:
  <out>/v<version>/PLAN.md                   ← parent task body (Plan + Konzept)
  <out>/v<version>/prompts/NNN-kebab.md       ← subtask bodies

Usage:
  CLICKUP_TOKEN=pk_xxx python3 scripts/download-clickup-prompts.py [--out <dir>]
"""
import json, os, sys, re, urllib.request
from pathlib import Path

LIST_ID = "901524055126"
TOKEN = os.environ.get("CLICKUP_TOKEN")
if not TOKEN:
    sys.exit("CLICKUP_TOKEN env var not set. Set it from your ClickUp Personal API Token.")
API = "https://api.clickup.com/api/v2"

OUT = Path(sys.argv[sys.argv.index("--out")+1]) if "--out" in sys.argv else Path("docs/clickup-snapshot")
OUT.mkdir(parents=True, exist_ok=True)

def get(path):
    req = urllib.request.Request(f"{API}{path}", headers={"Authorization": TOKEN})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def kebab(s):
    s = re.sub(r'[`*_]+', '', s)
    s = re.sub(r'[^a-zA-Z0-9]+', '-', s.lower())
    return re.sub(r'-+','-', s).strip('-')[:80]

tasks = []
page = 0
while True:
    data = get(f"/list/{LIST_ID}/task?page={page}&include_closed=true&subtasks=true")
    if not data.get("tasks"): break
    tasks.extend(data["tasks"])
    if data.get("last_page", True): break
    page += 1
print(f"Fetched {len(tasks)} tasks from ClickUp.")

stats = {}
for t in tasks:
    name = t["name"]
    body = t.get("markdown_description") or t.get("description") or ""
    m = re.match(r'^\[(V[\d.]+)\s+P([\d]{3}[a-z]?)\]\s+(.+)$', name)
    if m:
        short_v, num, title = m.groups()
        ver = short_v[1:]
        if "." not in ver.split(".",1)[1]: ver = ver + ".00"
        d = OUT / f"v{ver}" / "prompts"
        d.mkdir(parents=True, exist_ok=True)
        d.joinpath(f"{num}-{kebab(title)}.md").write_text(body)
        stats[short_v] = stats.get(short_v,0) + 1
    elif "Implementation Plan" in name:
        ver = name.split()[0][1:]
        if "." not in ver.split(".",1)[1]: ver = ver + ".00"
        d = OUT / f"v{ver}"
        d.mkdir(parents=True, exist_ok=True)
        d.joinpath("PLAN.md").write_text(body)
        stats[f"{name.split()[0]} (parent)"] = 1

print(f"\nWritten to {OUT}/:")
for k,v in sorted(stats.items()):
    print(f"  {k:30s} {v}")
