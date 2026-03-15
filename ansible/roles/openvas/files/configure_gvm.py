#!/usr/bin/env python3
"""
CCDC OpenVAS/GVM Configuration Script
Creates credentials, targets, and scan tasks for all CCDC hosts.
Run via: gvm-script --gmp-username admin --gmp-password <pw> socket configure_gvm.py
"""

import sys
import os
import json
import time
from argparse import Namespace

# python-gvm imports
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmError

# ---------------------------------------------------------------------------
# Configuration injected by Ansible (written to /tmp/gvm_config.json)
# ---------------------------------------------------------------------------
CONFIG_FILE = "/tmp/gvm_config.json"

with open(CONFIG_FILE) as f:
    cfg = json.load(f)

ADMIN_PASSWORD     = cfg["admin_password"]
SSH_LOGIN          = cfg["ssh_login"]
SSH_PRIVATE_KEY    = cfg["ssh_private_key"]
SMB_LOGIN          = cfg["smb_login"]
SMB_PASSWORD       = cfg["smb_password"]
LINUX_HOSTS        = cfg["linux_hosts"]        # list of IPs
WINDOWS_HOSTS      = cfg["windows_hosts"]      # list of IPs
SCAN_CONFIG_NAME   = cfg["scan_config"]        # "Full and Fast" etc.
PORT_LIST_NAME     = cfg["port_list"]
ALIVE_TEST_NAME    = cfg["alive_test"]
MAX_HOSTS          = cfg["max_hosts"]
MAX_CHECKS         = cfg["max_checks"]

# Well-known GVM UUIDs (consistent across installations)
SCAN_CONFIG_UUIDS = {
    "Full and Fast":           "daba56c8-73ec-11df-a475-002264764cea",
    "Full and Fast Ultimate":  "698f691e-7489-11df-9d8c-002264764cea",
    "Full and Very Deep":      "708f25c4-7489-11df-8094-002264764cea",
    "System Discovery":        "bbca7412-a950-11e3-9109-406186ea4fc5",
    "Host Discovery":          "2d3be9a5-e9ab-11e6-8f8e-406186ea4fc5",
}

PORT_LIST_UUIDS = {
    "All TCP":                             "fd591a34-56fd-11e1-9f27-406186ea4fc5",
    "All IANA assigned TCP":               "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
    "All TCP and Nmap top 100 UDP":        "730ef368-57e2-11e1-a90f-406186ea4fc5",
    "All TCP and Nmap top 1000 UDP":       "4a4717fe-57d2-11e1-9a26-406186ea4fc5",
}

DEFAULT_SCANNER_UUID = "08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS Default

ALIVE_TEST_MAP = {
    "Consider Alive":  "Consider Alive",
    "ICMP Ping":       "ICMP Ping",
    "TCP-ACK Service": "TCP-ACK Service Ping",
    "TCP-SYN Service": "TCP-SYN Service Ping",
    "ARP Ping":        "ARP Ping",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_or_create(gmp, entity_type, name, creator_fn):
    """Return the ID of an existing entity by name, or create it."""
    response = getattr(gmp, f"get_{entity_type}s")(filter_string=f'name="{name}"')
    items = response.findall(entity_type)
    for item in items:
        if item.findtext("name") == name:
            uid = item.get("id")
            print(f"  Reusing existing {entity_type}: {name} ({uid})")
            return uid
    print(f"  Creating {entity_type}: {name}")
    result = creator_fn()
    uid = result.find(entity_type).get("id")
    return uid


def find_scan_config(gmp, name):
    uuid = SCAN_CONFIG_UUIDS.get(name)
    if uuid:
        return uuid
    # Fall back to querying by name
    r = gmp.get_scan_configs(filter_string=f'name="{name}"')
    for sc in r.findall("config"):
        if sc.findtext("name") == name:
            return sc.get("id")
    # Default to Full and Fast if not found
    print(f"  WARNING: scan config '{name}' not found, using 'Full and Fast'")
    return SCAN_CONFIG_UUIDS["Full and Fast"]


def find_port_list(gmp, name):
    uuid = PORT_LIST_UUIDS.get(name)
    if uuid:
        return uuid
    r = gmp.get_port_lists(filter_string=f'name="{name}"')
    for pl in r.findall("port_list"):
        if pl.findtext("name") == name:
            return pl.get("id")
    print(f"  WARNING: port list '{name}' not found, using 'All TCP and Nmap top 100 UDP'")
    return PORT_LIST_UUIDS["All TCP and Nmap top 100 UDP"]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

connection = UnixSocketConnection(path="/run/gvmd/gvmd.sock")
transform  = EtreeCheckCommandTransform()

with Gmp(connection=connection, transform=transform) as gmp:
    # Authenticate
    gmp.authenticate("admin", ADMIN_PASSWORD)
    print("[+] Authenticated to GVM")

    # ------------------------------------------------------------------
    # 1. SSH credential for Linux authenticated scanning
    # ------------------------------------------------------------------
    print("\n[+] Setting up credentials...")

    ssh_cred_id = None
    # Check if already exists
    r = gmp.get_credentials(filter_string=f'name="{cfg["ssh_cred_name"]}"')
    for c in r.findall("credential"):
        if c.findtext("name") == cfg["ssh_cred_name"]:
            ssh_cred_id = c.get("id")
            print(f"  Reusing SSH credential: {cfg['ssh_cred_name']} ({ssh_cred_id})")
            break

    if not ssh_cred_id:
        r = gmp.create_credential(
            name=cfg["ssh_cred_name"],
            credential_type=gmp.types.CredentialType.USERNAME_SSH_KEY,
            login=SSH_LOGIN,
            private_key=SSH_PRIVATE_KEY,
        )
        ssh_cred_id = r.find("credential").get("id")
        print(f"  Created SSH credential: {cfg['ssh_cred_name']} ({ssh_cred_id})")

    # ------------------------------------------------------------------
    # 2. SMB/password credential for Windows authenticated scanning
    # ------------------------------------------------------------------
    smb_cred_id = None
    if SMB_PASSWORD:
        r = gmp.get_credentials(filter_string=f'name="{cfg["smb_cred_name"]}"')
        for c in r.findall("credential"):
            if c.findtext("name") == cfg["smb_cred_name"]:
                smb_cred_id = c.get("id")
                print(f"  Reusing SMB credential: {cfg['smb_cred_name']} ({smb_cred_id})")
                break

        if not smb_cred_id:
            r = gmp.create_credential(
                name=cfg["smb_cred_name"],
                credential_type=gmp.types.CredentialType.USERNAME_PASSWORD,
                login=SMB_LOGIN,
                password=SMB_PASSWORD,
            )
            smb_cred_id = r.find("credential").get("id")
            print(f"  Created SMB credential: {cfg['smb_cred_name']} ({smb_cred_id})")

    # ------------------------------------------------------------------
    # 3. Look up scan config and port list
    # ------------------------------------------------------------------
    scan_config_id = find_scan_config(gmp, SCAN_CONFIG_NAME)
    port_list_id   = find_port_list(gmp, PORT_LIST_NAME)
    print(f"\n[+] Scan config: {SCAN_CONFIG_NAME} ({scan_config_id})")
    print(f"[+] Port list:   {PORT_LIST_NAME} ({port_list_id})")

    # ------------------------------------------------------------------
    # 4. Create target: Linux hosts
    # ------------------------------------------------------------------
    print("\n[+] Setting up scan targets...")
    task_ids = []

    if LINUX_HOSTS:
        linux_hosts_str = ", ".join(LINUX_HOSTS)
        target_name = "CCDC-Linux-Hosts"
        linux_target_id = None

        r = gmp.get_targets(filter_string=f'name="{target_name}"')
        for t in r.findall("target"):
            if t.findtext("name") == target_name:
                linux_target_id = t.get("id")
                print(f"  Reusing target: {target_name} ({linux_target_id})")
                break

        if not linux_target_id:
            kwargs = dict(
                name=target_name,
                hosts=[linux_hosts_str],
                port_list_id=port_list_id,
                alive_test=gmp.types.AliveTest.CONSIDER_ALIVE,
                ssh_credential_id=ssh_cred_id,
                ssh_credential_port=22,
            )
            r = gmp.create_target(**kwargs)
            linux_target_id = r.find("target").get("id")
            print(f"  Created target: {target_name} ({linux_target_id})")
            print(f"    Hosts: {linux_hosts_str}")

        # Create Linux scan task
        task_name = "CCDC-Scan-Linux"
        r = gmp.get_tasks(filter_string=f'name="{task_name}"')
        existing = [t for t in r.findall("task") if t.findtext("name") == task_name]
        if existing:
            linux_task_id = existing[0].get("id")
            print(f"  Reusing task: {task_name} ({linux_task_id})")
        else:
            r = gmp.create_task(
                name=task_name,
                config_id=scan_config_id,
                target_id=linux_target_id,
                scanner_id=DEFAULT_SCANNER_UUID,
                preferences={
                    "max_hosts":   str(MAX_HOSTS),
                    "max_checks":  str(MAX_CHECKS),
                },
            )
            linux_task_id = r.find("task").get("id")
            print(f"  Created task: {task_name} ({linux_task_id})")

        task_ids.append(linux_task_id)

    # ------------------------------------------------------------------
    # 5. Create target: Windows hosts
    # ------------------------------------------------------------------
    if WINDOWS_HOSTS:
        windows_hosts_str = ", ".join(WINDOWS_HOSTS)
        target_name = "CCDC-Windows-Hosts"
        windows_target_id = None

        r = gmp.get_targets(filter_string=f'name="{target_name}"')
        for t in r.findall("target"):
            if t.findtext("name") == target_name:
                windows_target_id = t.get("id")
                print(f"  Reusing target: {target_name} ({windows_target_id})")
                break

        if not windows_target_id:
            kwargs = dict(
                name=target_name,
                hosts=[windows_hosts_str],
                port_list_id=port_list_id,
                alive_test=gmp.types.AliveTest.CONSIDER_ALIVE,
            )
            if smb_cred_id:
                kwargs["smb_credential_id"] = smb_cred_id
            r = gmp.create_target(**kwargs)
            windows_target_id = r.find("target").get("id")
            print(f"  Created target: {target_name} ({windows_target_id})")
            print(f"    Hosts: {windows_hosts_str}")

        # Create Windows scan task
        task_name = "CCDC-Scan-Windows"
        r = gmp.get_tasks(filter_string=f'name="{task_name}"')
        existing = [t for t in r.findall("task") if t.findtext("name") == task_name]
        if existing:
            windows_task_id = existing[0].get("id")
            print(f"  Reusing task: {task_name} ({windows_task_id})")
        else:
            r = gmp.create_task(
                name=task_name,
                config_id=scan_config_id,
                target_id=windows_target_id,
                scanner_id=DEFAULT_SCANNER_UUID,
                preferences={
                    "max_hosts":   str(MAX_HOSTS),
                    "max_checks":  str(MAX_CHECKS),
                },
            )
            windows_task_id = r.find("task").get("id")
            print(f"  Created task: {task_name} ({windows_task_id})")

        task_ids.append(windows_task_id)

    # ------------------------------------------------------------------
    # 6. Save task IDs for the scan step
    # ------------------------------------------------------------------
    output = {"task_ids": task_ids}
    with open("/tmp/gvm_tasks.json", "w") as f:
        json.dump(output, f)

    print(f"\n[+] Configuration complete. {len(task_ids)} task(s) ready.")
    print(f"    Task IDs written to /tmp/gvm_tasks.json")
    print(f"    Web UI: https://localhost:9392  (admin / <vault password>)")
