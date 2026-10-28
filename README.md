# Blue Team Detection Web App

A small Flask-based SOC-style dashboard that ingests multiple log sources, normalizes events, scores detections from 0–100, correlates related alerts into incidents, and exports a report.

## Features
- Upload and ingest multiple log files
- Run a sample demo with bundled logs
- Normalize SSH, Apache, Windows EVTX, and firewall logs
- Run detection rules with 0–100 risk scores
- Correlate alerts into incidents
- View case pages for each incident
- MITRE ATT&CK mapping per rule
- Export a final report

## Install
```bash
pip install -r requirements.txt
```

## Run
```bash
python app.py
```

Open `http://127.0.0.1:5000`.

## Supported files
- `auth.log`
- `access.log`
- `security.evtx`
- `firewall.log`

## Demo
The home page includes a **Run sample demo** button that scans the bundled sample logs in the `samples/` folder.

## Notes
- This is designed as a local training/demo tool.
- The website stores scan results in memory for the current session.
- Upload your own logs or use the sample files in `samples/`.
