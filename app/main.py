
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Any
import xml.etree.ElementTree as ET
import json
import os
import re
import hashlib
import httpx
from collections import defaultdict
from datetime import datetime

MAX_FILES = int(os.getenv("MAX_FILES", "20"))
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "10"))
MAX_EVENTS_RETURNED = int(os.getenv("MAX_EVENTS_RETURNED", "1000"))

app = FastAPI(title="Sysmon AI Analyst", version="0.1.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

class AnalyzeRequest(BaseModel):
    events: list[dict[str, Any]]
    max_context_events: int = Field(default=80, ge=1, le=200)

def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()

def normalize_xml_event(root: ET.Element) -> dict[str, Any]:
    data = {}
    for child in root.iter():
        tag = child.tag.split("}")[-1]
        if tag in {"EventData", "System"}:
            continue
        if child.text and child.text.strip() and len(child) < 1:
            data[tag] = child.text.strip()

    system = root.find(".//{*}System")
    if system is not None:
        for child in system:
            tag = child.tag.split("}")[-1]
            if child.text and child.text.strip():
                data[tag] = child.text.strip()
            data.update({f"{tag}.{k}": v for k, v in child.attrib.items()})

    eventdata = root.find(".//{*}EventData")
    if eventdata is not None:
        for item in eventdata:
            name = item.attrib.get("Name", item.tag.split("}")[-1])
            data[name] = item.text.strip() if item.text else ""

    event_id = data.get("EventID") or data.get("EventID.#text")
    try:
        event_id = int(event_id)
    except Exception:
        pass

    return {
        "event_id": event_id,
        "provider": data.get("Provider.Name") or data.get("Provider"),
        "computer": data.get("Computer"),
        "channel": data.get("Channel"),
        "time": data.get("TimeCreated.SystemTime") or data.get("UtcTime"),
        "image": data.get("Image"),
        "parent_image": data.get("ParentImage"),
        "command_line": data.get("CommandLine"),
        "user": data.get("User") or data.get("UserName"),
        "process_guid": data.get("ProcessGuid"),
        "parent_guid": data.get("ParentProcessGuid"),
        "process_id": data.get("ProcessId"),
        "parent_process_id": data.get("ParentProcessId"),
        "hashes": data.get("Hashes"),
        "destination_ip": data.get("DestinationIp"),
        "destination_port": data.get("DestinationPort"),
        "query_name": data.get("QueryName"),
        "target_filename": data.get("TargetFilename"),
        "raw_fields": data,
    }

def parse_xml(content: bytes) -> list[dict[str, Any]]:
    text = content.decode("utf-8", errors="replace")
    events = []
    # Support both Event XML files and files containing multiple <Event> elements.
    try:
        root = ET.fromstring(text)
        candidates = [root] if root.tag.split("}")[-1] == "Event" else root.findall(".//{*}Event")
        if not candidates:
            candidates = list(root)
        for event in candidates:
            events.append(normalize_xml_event(event))
    except ET.ParseError:
        # Try line-oriented Event fragments.
        fragments = re.findall(r"<Event\b.*?</Event>", text, flags=re.S | re.I)
        for fragment in fragments:
            try:
                events.append(normalize_xml_event(ET.fromstring(fragment)))
            except ET.ParseError:
                continue
    return events

def parse_json(content: bytes) -> list[dict[str, Any]]:
    obj = json.loads(content.decode("utf-8", errors="replace"))
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and isinstance(obj.get("events"), list):
        return obj["events"]
    return [obj]

def risk_score(event: dict[str, Any]) -> tuple[int, list[str]]:
    score, reasons = 0, []
    image = (event.get("image") or "").lower()
    parent = (event.get("parent_image") or "").lower()
    cmd = (event.get("command_line") or "").lower()

    if event.get("event_id") == 1:
        score += 10
    if "winword.exe" in parent or "excel.exe" in parent or "outlook.exe" in parent:
        if any(x in image for x in ("powershell", "cmd.exe", "wscript", "cscript", "mshta")):
            score += 35
            reasons.append("Office application spawned a script interpreter")
    if "powershell" in image:
        score += 15
        if any(x in cmd for x in ("-enc", "encodedcommand", "frombase64string")):
            score += 30
            reasons.append("PowerShell encoded/base64-like command")
    if image.endswith("\\rundll32.exe") or image.endswith("/rundll32.exe"):
        score += 15
        reasons.append("rundll32 execution")
    if event.get("destination_ip") or event.get("destination_port"):
        score += 10
        reasons.append("Network activity associated with process")
    if event.get("target_filename"):
        score += 5
    return min(score, 100), reasons

def enrich(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for e in events:
        score, reasons = risk_score(e)
        e = dict(e)
        e["risk_score"] = score
        e["risk_reasons"] = reasons
        out.append(e)
    return sorted(out, key=lambda x: (x.get("risk_score", 0), x.get("time") or ""), reverse=True)

@app.get("/")
async def index():
    return FileResponse("static/index.html")

@app.post("/api/upload")
async def upload(files: list[UploadFile] = File(...)):
    if len(files) > MAX_FILES:
        raise HTTPException(413, f"Maximum {MAX_FILES} files per upload")

    all_events = []
    file_info = []
    for f in files:
        content = await f.read()
        if len(content) > MAX_FILE_MB * 1024 * 1024:
            raise HTTPException(413, f"{f.filename}: file exceeds {MAX_FILE_MB} MB")
        name = (f.filename or "").lower()
        if name.endswith(".json") or name.endswith(".ndjson"):
            try:
                events = parse_json(content)
            except Exception as exc:
                raise HTTPException(400, f"{f.filename}: invalid JSON ({exc})")
        else:
            events = parse_xml(content)

        for e in events:
            e["source_file"] = f.filename
        all_events.extend(events)
        file_info.append({"name": f.filename, "events": len(events), "bytes": len(content)})

    all_events = enrich(all_events)
    return {
        "files": file_info,
        "event_count": len(all_events),
        "events": all_events[:MAX_EVENTS_RETURNED],
        "truncated": len(all_events) > MAX_EVENTS_RETURNED,
    }

@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest):
    api_key = os.getenv("LLM_API_KEY")
    base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("LLM_MODEL", "gpt-4.1-mini")

    if not api_key:
        raise HTTPException(503, "LLM is not configured. Set LLM_API_KEY on the server.")

    selected = sorted(req.events, key=lambda e: e.get("risk_score", 0), reverse=True)[:req.max_context_events]

    # Minimize sensitive payload: send a curated context, not raw full events.
    context = []
    for e in selected:
        context.append({
            "event_id": e.get("event_id"),
            "computer": e.get("computer"),
            "time": e.get("time"),
            "image": e.get("image"),
            "parent_image": e.get("parent_image"),
            "command_line": e.get("command_line"),
            "user": e.get("user"),
            "destination_ip": e.get("destination_ip"),
            "destination_port": e.get("destination_port"),
            "query_name": e.get("query_name"),
            "target_filename": e.get("target_filename"),
            "risk_score": e.get("risk_score"),
            "risk_reasons": e.get("risk_reasons"),
        })

    system = """You are a SOC threat-hunting analyst. Analyze the supplied Sysmon context.
Return ONLY valid JSON with keys:
verdict (string), severity (low|medium|high|critical), confidence (0..1),
summary (string), evidence (array of strings), attack_techniques (array of objects with id,name),
recommended_hunting_queries (array of strings).
Do not invent facts. Clearly distinguish observations from hypotheses."""

    payload = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False)}
        ],
        "response_format": {"type": "json_object"}
    }

    async with httpx.AsyncClient(timeout=60) as client:
        try:
            response = await client.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            result = json.loads(content)
        except httpx.HTTPError as exc:
            raise HTTPException(502, f"LLM API error: {exc}")
        except (KeyError, json.JSONDecodeError) as exc:
            raise HTTPException(502, f"Invalid LLM response: {exc}")

    return {
        "provider": base_url,
        "model": model,
        "context_events": len(selected),
        "analysis": result
    }
