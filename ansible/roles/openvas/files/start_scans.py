#!/usr/bin/env python3
"""
CCDC OpenVAS — Start Scan Tasks and Monitor Progress
Reads task IDs from /tmp/gvm_tasks.json, starts each scan,
then polls until complete and exports the report.
"""

import json
import sys
import time
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

CONFIG_FILE = "/tmp/gvm_config.json"
TASKS_FILE  = "/tmp/gvm_tasks.json"

with open(CONFIG_FILE) as f:
    cfg = json.load(f)
with open(TASKS_FILE) as f:
    tasks_cfg = json.load(f)

ADMIN_PASSWORD = cfg["admin_password"]
TASK_IDS       = tasks_cfg["task_ids"]
REPORT_FORMAT  = cfg.get("report_format", "XML")
REPORT_DIR     = cfg.get("report_dir", "/tmp/openvas_reports")

import os
os.makedirs(REPORT_DIR, exist_ok=True)

# Report format UUIDs
REPORT_FORMAT_UUIDS = {
    "XML":  "a994b278-1f62-11e1-96ac-406186ea4fc5",
    "PDF":  "c402cc3e-b531-11e1-9163-406186ea4fc5",
    "HTML": "6c248850-1f62-11e1-b082-406186ea4fc5",
    "CSV":  "c1645568-627a-11e3-a660-406186ea4fc5",
}

connection = UnixSocketConnection(path="/run/gvmd/gvmd.sock")
transform  = EtreeCheckCommandTransform()

with Gmp(connection=connection, transform=transform) as gmp:
    gmp.authenticate("admin", ADMIN_PASSWORD)
    print("[+] Authenticated to GVM")

    report_format_id = REPORT_FORMAT_UUIDS.get(REPORT_FORMAT, REPORT_FORMAT_UUIDS["XML"])

    running_tasks = []

    # Start all tasks
    for task_id in TASK_IDS:
        r = gmp.get_task(task_id=task_id)
        task_elem = r.find("task")
        task_name = task_elem.findtext("name")
        status = task_elem.findtext("status")

        if status in ("Running", "Requested", "Queued"):
            print(f"  Task already running: {task_name} [{status}]")
            running_tasks.append((task_id, task_name))
        elif status == "Done":
            print(f"  Task already completed: {task_name} — will re-run")
            gmp.start_task(task_id=task_id)
            running_tasks.append((task_id, task_name))
        else:
            print(f"  Starting task: {task_name}")
            gmp.start_task(task_id=task_id)
            running_tasks.append((task_id, task_name))

    if not running_tasks:
        print("No tasks to run.")
        sys.exit(0)

    print(f"\n[+] {len(running_tasks)} scan(s) started. Monitoring...")
    print("    Check progress in the web UI: https://localhost:9392")
    print("    This script will poll every 60s and export reports when done.\n")

    completed = set()
    while len(completed) < len(running_tasks):
        time.sleep(60)
        for task_id, task_name in running_tasks:
            if task_id in completed:
                continue
            r = gmp.get_task(task_id=task_id)
            task_elem = r.find("task")
            status    = task_elem.findtext("status")
            progress  = task_elem.findtext("progress") or "?"
            print(f"  [{time.strftime('%H:%M:%S')}] {task_name}: {status} {progress}%")

            if status == "Done":
                print(f"  [+] {task_name} completed — exporting report")
                # Get the latest report ID
                report_id = task_elem.find(".//last_report/report").get("id")
                report_data = gmp.get_report(
                    report_id=report_id,
                    report_format_id=report_format_id,
                    filter_string="levels=hmlgd",   # high, medium, low, general, debug
                    ignore_pagination=True,
                )
                # Extract and save report content
                ext = REPORT_FORMAT.lower()
                report_path = os.path.join(REPORT_DIR, f"{task_name.replace(' ', '_')}_{time.strftime('%Y%m%d_%H%M')}.{ext}")
                report_content = report_data.find(".//report")
                if report_content is not None:
                    import xml.etree.ElementTree as ET
                    with open(report_path, "wb") as f:
                        f.write(ET.tostring(report_content, encoding="unicode").encode())
                    print(f"    Report saved: {report_path}")
                else:
                    # Try raw encoded content (PDF uses base64)
                    raw = report_data.find(".//report[@content_type]")
                    if raw is not None and raw.text:
                        import base64
                        with open(report_path, "wb") as f:
                            f.write(base64.b64decode(raw.text))
                        print(f"    Report saved: {report_path}")

                completed.add(task_id)

    print(f"\n[+] All scans complete. Reports in: {REPORT_DIR}")
