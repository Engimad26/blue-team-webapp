from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from engine.ingest import ingest_files
from engine.report import build_report, save_report
from engine.database import load_alerts

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "output"
SAMPLE_DIR = BASE_DIR / "samples"

UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = "blue-team-demo-secret"
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

SCANS: dict[str, dict] = {}
SCAN_ORDER: list[str] = []


MITRE_RULES = [
    ("sql injection", ("Initial Access", "Exploit Public-Facing Application", "T1190")),
    ("directory traversal", ("Initial Access", "Exploit Public-Facing Application", "T1190")),
    ("brute force", ("Credential Access", "Brute Force", "T1110")),
    ("success after failures", ("Credential Access", "Brute Force", "T1110")),
    ("invalid user", ("Credential Access", "Brute Force", "T1110")),
    ("log cleared", ("Defense Evasion", "Indicator Removal on Host", "T1070")),
    ("admin privileges", ("Privilege Escalation", "Abuse Elevation Control Mechanism", "T1548")),
    ("web scanning", ("Discovery", "Network Service Scanning", "T1046")),
    ("port scan", ("Discovery", "Network Service Scanning", "T1046")),
    ("blocked connections", ("Discovery", "Network Service Scanning", "T1046")),
    ("powershell", ("Execution", "Command and Scripting Interpreter", "T1059")),
]


def infer_mitre_fields(alert: dict) -> tuple[str, str, str]:
    blob = " ".join(
        [
            str(alert.get("source", "")),
            str(alert.get("rule", "")),
            str(alert.get("message", "")),
            str(alert.get("mitre", "")),
        ]
    ).lower()

    for needle, mapping in MITRE_RULES:
        if needle in blob:
            return mapping

    return (
        "Unknown tactic",
        "Unknown technique",
        str(alert.get("mitre", "TBD")),
    )


def _scan_and_store(paths: list[Path], *, label: str) -> str:

    scan_id = str(uuid4())[:8]

    alerts, incidents, stats, sources = ingest_files(paths)

    report = build_report(
        scan_id=scan_id,
        alerts=alerts,
        incidents=incidents,
        stats=stats,
        sources=sources,
        label=label,
    )

    report_path = save_report(
        report,
        scan_id=scan_id,
        output_dir=OUTPUT_DIR,
    )

    SCANS[scan_id] = {
        "scan_id": scan_id,
        "label": label,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "alerts": alerts,
        "incidents": incidents,
        "stats": stats,
        "sources": sources,
        "report_path": str(report_path),
        "report": report,
    }

    SCAN_ORDER.append(scan_id)

    return scan_id


@app.get("/")
def index():

    latest = SCANS.get(SCAN_ORDER[-1]) if SCAN_ORDER else None

    history = [SCANS[sid] for sid in reversed(SCAN_ORDER[-5:])]

    db_alerts = load_alerts()

    return render_template(
        "index.html",
        latest=latest,
        history=history,
        db_alerts=db_alerts,
    )


@app.post("/scan")
def scan():

    files = request.files.getlist("logs")

    if not files or all(f.filename == "" for f in files):
        flash("Please choose at least one log file.", "error")
        return redirect(url_for("index"))

    saved_paths = []

    for file in files:

        if file.filename == "":
            continue

        filename = Path(file.filename).name

        destination = UPLOAD_DIR / filename

        file.save(destination)

        saved_paths.append(destination)

    scan_id = _scan_and_store(
        saved_paths,
        label="Uploaded logs",
    )

    return redirect(url_for("dashboard", scan_id=scan_id))


def _sample_paths():

    if not SAMPLE_DIR.exists():
        return []

    return [
        path
        for path in sorted(SAMPLE_DIR.iterdir())
        if path.is_file()
    ]


@app.post("/samples")
def load_samples():

    sample_paths = _sample_paths()

    if not sample_paths:
        flash("No sample logs found.", "error")
        return redirect(url_for("index"))

    scan_id = _scan_and_store(
        sample_paths,
        label="Project sample logs",
    )

    return redirect(url_for("dashboard", scan_id=scan_id))


@app.post("/demo")
def demo():
    return load_samples()


@app.get("/dashboard/<scan_id>")
def dashboard(scan_id):

    scan = SCANS.get(scan_id)

    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("index"))

    return render_template(
        "dashboard.html",
        scan=scan,
    )


@app.get("/mitre/<scan_id>")
def mitre(scan_id):

    scan = SCANS.get(scan_id)

    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("index"))

    mappings = []

    for alert in scan["alerts"]:

        if not isinstance(alert, dict):
            continue

        tactic, technique, mitre_id = infer_mitre_fields(alert)

        mappings.append(
            {
                "score": alert.get("score", 0),
                "source": alert.get("source", "Unknown"),
                "rule": alert.get("rule", "Unknown"),
                "mitre": alert.get("mitre", mitre_id),
                "tactic": alert.get("tactic", tactic),
                "technique": alert.get("technique", technique),
                "message": alert.get("message", ""),
            }
        )

    return render_template(
        "mitre.html",
        scan=scan,
        mappings=mappings,
    )


@app.get("/case/<scan_id>/<incident_id>")
def case(scan_id, incident_id):

    scan = SCANS.get(scan_id)

    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("index"))

    incident = next(
        (
            incident
            for incident in scan["incidents"]
            if incident["id"] == incident_id
        ),
        None,
    )

    if not incident:
        flash("Incident not found.", "error")
        return redirect(url_for("dashboard", scan_id=scan_id))

    return render_template(
        "case.html",
        scan=scan,
        incident=incident,
    )


@app.get("/download/<scan_id>")
def download(scan_id):

    scan = SCANS.get(scan_id)

    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("index"))

    return send_file(
        scan["report_path"],
        as_attachment=True,
        download_name=f"final_report_{scan_id}.txt",
    )


if __name__ == "__main__":
    app.run(debug=True)