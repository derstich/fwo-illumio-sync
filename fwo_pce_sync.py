#!/usr/bin/env python3
"""
FWO ↔ Illumio PCE Bidirectional Sync  (v3)
==========================================
LABEL STRATEGY:
  Each PCE workload gets label  ar=WL-<primary_IP>  (key "ar", unique per workload).
  FWO host objects are named    WL-<primary_IP>      with obj_uid = PCE ar-label href.
  This makes FWO fully IP-based while PCE uses labels for policy enforcement.

IMPORT  (PCE → FWO):
  1. Create PCE label ar=WL-<IP> for each managed workload (if not exists)
  2. Assign that label to the workload in PCE (replaces old ar label)
  3. Create FWO host object  WL-<IP>  with obj_uid = ar-label href
  4. Create FWO object groups from PCE labels (role, env, bu, app, loc)
     Group name: PCE_<key>_<value>   obj_uid = PCE label href
  5. Assign host objects to their groups via FWO objgrp

EXPORT  (FWO → PCE):
  - FWO rules (Illumio_Demo mgm) → PCE rulesets  FWO_<rulename>
  - Objects mapped via obj_uid → PCE label hrefs → actors in PCE rules
  - Provision (commit) PCE draft policy

Usage:
  python3 fwo_pce_sync.py [--import-only] [--export-only] [--dry-run] [--debug]
"""

import sys, json, re, ipaddress, argparse, logging
from datetime import datetime, timezone
import requests
from requests.auth import HTTPBasicAuth

# ── Config ─────────────────────────────────────────────────────────────────────

FWO_GRAPHQL   = "https://localhost:9443/api/v1/graphql"
FWO_AUTH_URL  = "http://localhost:8880/api/AuthenticationToken/Get"
FWO_USER      = "admin"
FWO_PASS      = "<fwo-admin-password>"
FWO_MGM_ID    = 7   # Illumio_Demo
FWO_DEV_ID    = 7   # Illumio_PCE device
FWO_OWNER_ID  = 3   # Illumio_Demo_Owner (owner_network.owner_id)

PCE_BASE      = "https://<pce-hostname>:8443/api/v2"
PCE_ORG       = 1
PCE_USER      = "api_<key-id>"
PCE_PASS      = "<api-secret>"

PCE_AR_KEY    = "ar"                  # label key used for IP-based workload identity
PCE_AR_PREFIX = "WL-"                 # label value prefix: WL-172.24.50.165

# PCE label keys to create FWO object groups for
GROUP_LABEL_KEYS = ["role", "env", "app", "bu", "loc"]

RS_PREFIX     = "FWO_"               # prefix for PCE rulesets created by this script

VERIFY_SSL    = False
requests.packages.urllib3.disable_warnings()

# ── Logging ─────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("fwo_pce")

# ── PCE helpers ─────────────────────────────────────────────────────────────────

PCE_AUTH = HTTPBasicAuth(PCE_USER, PCE_PASS)
PCE_HDR  = {"Content-Type": "application/json"}

def pce_get(path, params=None):
    r = requests.get(PCE_BASE + path, auth=PCE_AUTH, params=params,
                     headers=PCE_HDR, verify=VERIFY_SSL)
    r.raise_for_status()
    return r.json()

def pce_post(path, body):
    r = requests.post(PCE_BASE + path, auth=PCE_AUTH,
                      headers=PCE_HDR, json=body, verify=VERIFY_SSL)
    if r.status_code not in (200, 201):
        log.error(f"POST {path} {r.status_code}: {r.text[:300]}")
    r.raise_for_status()
    return r.json()

def pce_put(href, body):
    r = requests.put(PCE_BASE + href, auth=PCE_AUTH,
                     headers=PCE_HDR, json=body, verify=VERIFY_SSL)
    if r.status_code not in (200, 201, 204):
        log.error(f"PUT {href} {r.status_code}: {r.text[:300]}")
    r.raise_for_status()

def pce_provision(dry_run):
    if dry_run:
        log.info("  [DRY] Would provision PCE policy")
        return
    r = requests.post(PCE_BASE + f"/orgs/{PCE_ORG}/sec_policy",
                      auth=PCE_AUTH, headers=PCE_HDR,
                      json={"update_description": "FWO sync"}, verify=VERIFY_SSL)
    if r.status_code in (200, 201):
        log.info("  Policy provisioned ✓")
    elif "nothing_to_commit" in r.text:
        log.info("  Nothing new to provision")
    else:
        log.warning(f"  Provision: {r.status_code} {r.text[:150]}")

def primary_ip(workload):
    """Return primary IPv4 (skip IPv6, docker, loopback). Handles managed and unmanaged workloads."""
    def _valid(addr):
        if not addr or ":" in addr or addr.startswith("172.17") or addr.startswith("127."):
            return False
        try:
            ipaddress.ip_address(addr.split("/")[0])
            return True
        except ValueError:
            return False

    # Managed workloads: use interfaces list
    for iface in workload.get("interfaces", []):
        addr = iface.get("address", "")
        if _valid(addr):
            return addr.split("/")[0]

    # Unmanaged workloads: may use ip_address field or labels
    addr = workload.get("ip_address") or workload.get("public_ip") or ""
    if _valid(addr):
        return addr.split("/")[0]

    return None

# ── Role-name helpers ───────────────────────────────────────────────────────────

def parse_role_name(name):
    """Return (env, app, role) if name matches <ENV>-<APP>-<ROLE>, else None."""
    m = ROLE_NAME_RE.match((name or "").upper())
    return (m.group(1), m.group(2), m.group(3)) if m else None


_label_cache = {}     # (key, segment) → href
_labels_by_key = {}   # key → [label objects]  — populated lazily per key


def _get_labels_for_key(key):
    if key not in _labels_by_key:
        _labels_by_key[key] = pce_get(f"/orgs/{PCE_ORG}/labels",
                                       {"key": key, "max_results": 500})
    return _labels_by_key[key]


def pce_ensure_label(key, value, dry_run):
    """Find or create a PCE label for key=value (exact, case-sensitive)."""
    cache_key = (key, value)
    if cache_key in _label_cache:
        return _label_cache[cache_key]

    for lbl in _get_labels_for_key(key):
        if lbl["value"] == value:
            _label_cache[cache_key] = lbl["href"]
            return lbl["href"]

    if dry_run:
        href = f"/orgs/{PCE_ORG}/labels/dry_{key}_{value}"
    else:
        result = pce_post(f"/orgs/{PCE_ORG}/labels", {"key": key, "value": value})
        href = result["href"]
        _labels_by_key[key].append({"href": href, "key": key, "value": value})
        log.info(f"  Created PCE label {key}={value}")
    _label_cache[cache_key] = href
    return href


def _clear_workload_role_labels(wl, dry_run):
    """Remove env/app/role labels from a workload no longer in any named role."""
    role_keys = {"env", "app", "role"}
    current   = wl.get("labels", [])
    to_remove = [l for l in current if l.get("key") in role_keys]
    if not to_remove:
        return
    new_labels   = [l for l in current if l.get("key") not in role_keys]
    hostname     = wl.get("hostname") or primary_ip(wl)
    removed_str  = ", ".join(f"{l['key']}={l.get('value','?')}" for l in to_remove)
    if dry_run:
        log.info(f"    [DRY] Would remove [{removed_str}] from {hostname}")
    else:
        pce_put(wl["href"], {"labels": [{"href": l["href"]} for l in new_labels]})
        log.info(f"    Removed [{removed_str}] from {hostname}")
    wl["labels"] = new_labels


def _set_workload_role_labels(wl, env_val, app_val, role_val, dry_run):
    """Set env/app/role labels on a workload, preserving all other labels."""
    env_href  = pce_ensure_label("env",  env_val,  dry_run)
    app_href  = pce_ensure_label("app",  app_val,  dry_run)
    role_href = pce_ensure_label("role", role_val, dry_run)

    current = wl.get("labels", [])
    cur_env  = next((l["href"] for l in current if l.get("key") == "env"),  None)
    cur_app  = next((l["href"] for l in current if l.get("key") == "app"),  None)
    cur_role = next((l["href"] for l in current if l.get("key") == "role"), None)
    if cur_env == env_href and cur_app == app_href and cur_role == role_href:
        return  # already correct

    new_labels = [l for l in current if l.get("key") not in ("env", "app", "role")]
    new_labels += [{"href": env_href,  "key": "env",  "value": env_val},
                   {"href": app_href,  "key": "app",  "value": app_val},
                   {"href": role_href, "key": "role", "value": role_val}]

    hostname = wl.get("hostname") or primary_ip(wl)
    if dry_run:
        log.info(f"    [DRY] Would set env={env_val}/app={app_val}/role={role_val} on {hostname}")
    else:
        pce_put(wl["href"], {"labels": [{"href": l["href"]} for l in new_labels]})
        log.info(f"    Set env={env_val}/app={app_val}/role={role_val} on {hostname}")
    wl["labels"] = new_labels  # update in-memory for subsequent operations


# ── FWO helpers ─────────────────────────────────────────────────────────────────

def fwo_token():
    r = requests.post(FWO_AUTH_URL,
                      json={"Username": FWO_USER, "Password": FWO_PASS,
                            "ProductName": "fworch"},
                      verify=VERIFY_SSL)
    r.raise_for_status()
    return r.text.strip()

def fwo_gql(token, query, variables=None):
    r = requests.post(FWO_GRAPHQL,
                      headers={"Authorization": f"Bearer {token}",
                               "Content-Type": "application/json"},
                      json={"query": query, "variables": variables or {}},
                      verify=VERIFY_SSL)
    r.raise_for_status()
    d = r.json()
    if "errors" in d:
        raise RuntimeError(f"GraphQL error: {d['errors']}")
    return d["data"]

def fwo_max_obj_id(token):
    d = fwo_gql(token, "{ object_aggregate { aggregate { max { obj_id } } } }")
    return d["object_aggregate"]["aggregate"]["max"]["obj_id"] or 1000

def fwo_get_objects(token):
    d = fwo_gql(token, """query($mgm: Int!) {
      object(where: {mgm_id: {_eq: $mgm}, active: {_eq: true}}) {
        obj_id obj_name obj_ip obj_ip_end obj_typ_id obj_uid obj_comment
      }
    }""", {"mgm": FWO_MGM_ID})
    return d["object"]

def fwo_get_objgrp_members(token):
    d = fwo_gql(token, """{ objgrp(where: {active: {_eq: true}}) {
      objgrp_id objgrp_member_id } }""")
    result = {}
    for row in d["objgrp"]:
        result.setdefault(row["objgrp_id"], set()).add(row["objgrp_member_id"])
    return result

def fwo_get_rules(token):
    d = fwo_gql(token, """query($mgm: Int!) {
      rule(where: {mgm_id: {_eq: $mgm}, active: {_eq: true},
                   rule_disabled: {_eq: false}}) {
        rule_id rule_name rule_action rule_comment
        rule_froms { object { obj_id obj_name obj_typ_id obj_uid } }
        rule_tos   { object { obj_id obj_name obj_typ_id obj_uid } }
        rule_services { service { svc_id svc_name svc_port svc_port_end ip_proto_id } }
      }
    }""", {"mgm": FWO_MGM_ID})
    return d["rule"]

def fwo_create_import_control(token):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    d = fwo_gql(token, """mutation($mgm: Int!, $t: timestamp!) {
      insert_import_control_one(object: {
        mgm_id: $mgm, successful_import: true, import_type_id: 1,
        start_time: $t, stop_time: $t
      }) { control_id }
    }""", {"mgm": FWO_MGM_ID, "t": now})
    return d["insert_import_control_one"]["control_id"]

def fwo_upsert_object(token, obj_id, name, ip, ic_id, uid, comment, typ_id, dry_run):
    if dry_run:
        log.info(f"    [DRY] upsert obj '{name}' {ip} typ={typ_id}")
        return
    fwo_gql(token, """mutation($id: bigint!, $name: String!, $ip: cidr!,
                               $ic: bigint!, $uid: String!, $comment: String!,
                               $typ: Int!, $mgm: Int!) {
      insert_object_one(object: {
        obj_id: $id, obj_name: $name, obj_ip: $ip, obj_ip_end: $ip,
        obj_typ_id: $typ, mgm_id: $mgm,
        obj_create: $ic, obj_last_seen: $ic,
        active: true, obj_uid: $uid, obj_comment: $comment
      },
      on_conflict: {constraint: object_pkey, update_columns:
        [obj_name, obj_ip, obj_ip_end, obj_last_seen, obj_uid,
         obj_comment, active]}) { obj_id }
    }""", {"id": obj_id, "name": name, "ip": ip, "ic": ic_id,
           "uid": uid, "comment": comment, "typ": typ_id, "mgm": FWO_MGM_ID})

def fwo_upsert_objgrp(token, grp_id, member_id, ic_id, dry_run):
    if dry_run:
        return
    fwo_gql(token, """mutation($gid: bigint!, $mid: bigint!, $ic: bigint!) {
      insert_objgrp_one(object: {
        objgrp_id: $gid, objgrp_member_id: $mid,
        import_created: $ic, import_last_seen: $ic, active: true
      },
      on_conflict: {constraint: objgrp_pkey,
        update_columns: [import_last_seen, active]}) { objgrp_id }
    }""", {"gid": grp_id, "mid": member_id, "ic": ic_id})
    fwo_gql(token, """mutation($gid: bigint!, $mid: bigint!, $ic: bigint!) {
      insert_objgrp_flat_one(object: {
        objgrp_flat_id: $gid, objgrp_flat_member_id: $mid,
        import_created: $ic, import_last_seen: $ic, active: true
      },
      on_conflict: {constraint: objgrp_flat_pkey,
        update_columns: [import_last_seen, active]}) { objgrp_flat_id }
    }""", {"gid": grp_id, "mid": member_id, "ic": ic_id})

def fwo_upsert_owner_network(name, ip, dry_run):
    """Ensure workload appears as App Server in Modelling (owner_network, nw_type=10)."""
    if dry_run:
        return
    import subprocess
    cidr = f"{ip}/32"
    sql = f"""
INSERT INTO owner_network (name, ip, ip_end, nw_type, owner_id, import_source, is_deleted)
SELECT '{name}', '{cidr}', '{cidr}', 10, {FWO_OWNER_ID}, 'pce_sync', false
WHERE NOT EXISTS (SELECT 1 FROM owner_network WHERE ip='{cidr}');
UPDATE owner_network SET name='{name}', nw_type=10, owner_id={FWO_OWNER_ID},
  is_deleted=false, import_source='pce_sync'
WHERE ip='{cidr}';
"""
    subprocess.run(['sudo', '-u', 'postgres', 'psql', '-d', 'fworchdb', '-c', sql],
                   capture_output=True)

# ── STEP 1: Label PCE workloads with ar=WL-<IP> ────────────────────────────────

def label_workloads_by_ip(workloads, dry_run):
    """
    Ensure every managed workload has label ar=WL-<primary_IP>.
    Returns dict: workload_href → ar_label_href
    """
    log.info("── STEP 1: PCE — assign ar=WL-<IP> labels to workloads ─────")

    # Load existing ar labels
    existing_ar = pce_get(f"/orgs/{PCE_ORG}/labels", {"key": PCE_AR_KEY, "max_results": 1000})
    ar_by_value = {l["value"]: l for l in existing_ar}
    log.info(f"  Existing ar-labels: {len(existing_ar)}")

    wl_to_ar_href = {}   # workload href → ar label href

    for wl in workloads:
        ip = primary_ip(wl)
        if not ip:
            continue

        wl_href   = wl["href"]
        ar_value  = f"{PCE_AR_PREFIX}{ip}"
        hostname  = wl.get("hostname") or ip

        # Get or create ar label
        if ar_value in ar_by_value:
            ar_label = ar_by_value[ar_value]
        else:
            if dry_run:
                log.info(f"  [DRY] Would create label ar={ar_value}")
                ar_label = {"href": f"/orgs/{PCE_ORG}/labels/dry_{ip}",
                            "value": ar_value}
            else:
                ar_label = pce_post(f"/orgs/{PCE_ORG}/labels",
                                    {"key": PCE_AR_KEY, "value": ar_value})
                ar_by_value[ar_value] = ar_label
                log.info(f"  Created label ar={ar_value}")

        wl_to_ar_href[wl_href] = ar_label["href"]

        # Check if workload already has this exact ar label
        current_labels = wl.get("labels", [])
        current_ar     = next((l for l in current_labels if l.get("key") == PCE_AR_KEY), None)

        if current_ar and current_ar.get("href") == ar_label["href"]:
            log.info(f"  {hostname:<35} ar={ar_value}  (already set)")
            continue

        # Replace ar label, keep all others
        new_labels = [l for l in current_labels if l.get("key") != PCE_AR_KEY]
        new_labels.append({"href": ar_label["href"]})

        if dry_run:
            log.info(f"  [DRY] Would set ar={ar_value} on {hostname}")
        else:
            pce_put(wl_href, {"labels": [{"href": l["href"]} for l in new_labels]})
            log.info(f"  {hostname:<35} → ar={ar_value}")

    log.info(f"  {len(wl_to_ar_href)} workloads labelled")
    return wl_to_ar_href

def _rebuild_latest_config(ic_id):
    """Rebuild latest_config JSON from current DB state after import."""
    import subprocess

    def psql(sql):
        r = subprocess.run(['sudo', '-u', 'postgres', 'psql', '-d', 'fworchdb', '-t', '-A', '-c', sql],
                           capture_output=True, text=True)
        return r.stdout.strip()

    rows = psql(f"""SELECT obj_uid, obj_name, obj_ip, obj_ip_end, obj_comment,
        CASE WHEN obj_typ_id=1 THEN 'host' WHEN obj_typ_id=2 THEN 'group'
             WHEN obj_typ_id=3 THEN 'ip_range' ELSE 'host' END
        FROM object WHERE mgm_id={FWO_MGM_ID} AND active=true
          AND obj_last_seen>={ic_id} AND removed IS NULL""")
    nw = {}
    for line in rows.splitlines():
        parts = line.split('|')
        if len(parts) < 6: continue
        uid, name, ip, ip_end, comment, typ = parts
        nw[uid] = {'obj_uid': uid, 'obj_name': name, 'obj_ip': ip,
                   'obj_ip_end': ip_end or ip, 'obj_comment': comment,
                   'obj_typ': typ, 'obj_color': 'black'}

    rule_rows = psql(f"""SELECT r.rule_uid, r.rule_name, r.rule_comment, r.rule_action, r.rule_track,
        string_agg(DISTINCT CASE WHEN rf.negated THEN '!' ELSE '' END || o1.obj_uid, ','),
        string_agg(DISTINCT CASE WHEN rt.negated THEN '!' ELSE '' END || o2.obj_uid, ',')
        FROM rule r
        LEFT JOIN rule_from rf ON rf.rule_id = r.rule_id
        LEFT JOIN object o1 ON o1.obj_id = rf.obj_id
        LEFT JOIN rule_to rt ON rt.rule_id = r.rule_id
        LEFT JOIN object o2 ON o2.obj_id = rt.obj_id
        WHERE r.mgm_id={FWO_MGM_ID} AND r.active=true
          AND r.rule_last_seen>={ic_id} AND r.removed IS NULL
        GROUP BY r.rule_uid, r.rule_name, r.rule_comment, r.rule_action, r.rule_track""")
    rules = {}
    for line in rule_rows.splitlines():
        parts = line.split('|')
        if len(parts) < 7: continue
        uid, name, comment, action, track, froms, tos = parts
        rules[uid or name] = {
            'rule_uid': uid or name, 'rule_name': name, 'rule_comment': comment,
            'rule_action': action or 'accept', 'rule_track': track or 'none',
            'rule_src': [f for f in froms.split(',') if f],
            'rule_dst': [t for t in tos.split(',') if t],
            'rule_svc': [], 'rule_disabled': False
        }

    config_json = json.dumps({'ConfigFormat': 'NORMALIZED', 'action': 'INSERT',
                               'network_objects': nw, 'rules': rules, 'services': {}})
    escaped = config_json.replace("'", "''")
    psql(f"UPDATE latest_config SET import_id={ic_id}, config='{escaped}'::jsonb WHERE mgm_id={FWO_MGM_ID};")
    log.info(f"  latest_config rebuilt: {len(nw)} objects, {len(rules)} rules")


# ── STEP 2: Import PCE workloads → FWO objects ─────────────────────────────────

def sync_import(token, workloads, wl_to_ar_href, dry_run):
    log.info("── STEP 2: FWO — import workloads as WL-<IP> objects ────────")

    # Load PCE labels for group-building
    all_pce_labels = pce_get(f"/orgs/{PCE_ORG}/labels", {"max_results": 1000})
    label_href_map = {(l["key"], l["value"]): l["href"] for l in all_pce_labels}

    # Load existing FWO objects
    existing     = fwo_get_objects(token)
    by_uid       = {o["obj_uid"]: o for o in existing if o.get("obj_uid")}
    by_name      = {o["obj_name"]: o for o in existing}
    existing_grp = fwo_get_objgrp_members(token)
    log.info(f"  FWO: {len(existing)} existing objects in Illumio_Demo")

    ic_id   = fwo_create_import_control(token) if not dry_run else 0
    next_id = fwo_max_obj_id(token) + 1
    changed = False  # track whether any write actually happened

    # ── 2a. Host objects  WL-<IP> ────────────────────────────────────────────
    log.info("  Creating host objects WL-<IP>...")
    wl_obj_map = {}   # workload_href → FWO obj_id

    for wl in workloads:
        ip       = primary_ip(wl)
        if not ip:
            continue
        wl_href  = wl["href"]
        ar_href  = wl_to_ar_href.get(wl_href, "")
        obj_name = f"{PCE_AR_PREFIX}{ip}"          # e.g. WL-172.24.50.165
        labels   = {l["key"]: l["value"] for l in wl.get("labels", [])}
        comment  = ", ".join(f"{k}={v}" for k, v in sorted(labels.items()))

        # Identify existing object: prefer match by ar-label uid, then by name
        if ar_href and ar_href in by_uid:
            existing_obj = by_uid[ar_href]
            obj_id = existing_obj["obj_id"]
            if existing_obj.get("obj_name") == obj_name and existing_obj.get("obj_uid") == ar_href:
                wl_obj_map[wl_href] = obj_id
                fwo_upsert_owner_network(obj_name, ip, dry_run)  # always ensure is_deleted=false
                continue
            action = "update"
        elif obj_name in by_name:
            existing_obj = by_name[obj_name]
            obj_id = existing_obj["obj_id"]
            if existing_obj.get("obj_uid") == ar_href:
                wl_obj_map[wl_href] = obj_id
                fwo_upsert_owner_network(obj_name, ip, dry_run)  # always ensure is_deleted=false
                continue
            action = "update"
        else:
            obj_id  = next_id
            next_id += 1
            action  = "create"

        fwo_upsert_object(token, obj_id, obj_name, f"{ip}/32",
                          ic_id, ar_href, comment, typ_id=3, dry_run=dry_run)
        fwo_upsert_owner_network(obj_name, ip, dry_run)
        wl_obj_map[wl_href] = obj_id
        changed = True
        log.info(f"    [{action}] {obj_name:<30} {ip}  (obj_id={obj_id})")

    # ── 2b. Object groups by PCE label ───────────────────────────────────────
    log.info("  Creating label-based object groups...")

    groups = {}   # (key, value) → [FWO obj_id, ...]
    for wl in workloads:
        wl_href = wl["href"]
        if wl_href not in wl_obj_map:
            continue
        for lbl in wl.get("labels", []):
            if lbl["key"] in GROUP_LABEL_KEYS:
                k = (lbl["key"], lbl["value"])
                groups.setdefault(k, []).append(wl_obj_map[wl_href])

    for (key, value), member_ids in sorted(groups.items()):
        grp_name  = f"PCE_{key}_{value}"
        pce_lhref = label_href_map.get((key, value), "")

        if grp_name in by_name:
            existing_grp_obj = by_name[grp_name]
            grp_id = existing_grp_obj["obj_id"]
            # Only upsert if uid changed
            if existing_grp_obj.get("obj_uid") != pce_lhref:
                fwo_upsert_object(token, grp_id, grp_name, "0.0.0.0/32",
                                  ic_id, pce_lhref,
                                  f"PCE label group {key}={value}",
                                  typ_id=2, dry_run=dry_run)
                changed = True
            action = "update"
        else:
            grp_id  = next_id
            next_id += 1
            action  = "create"
            fwo_upsert_object(token, grp_id, grp_name, "0.0.0.0/32",
                              ic_id, pce_lhref,
                              f"PCE label group {key}={value}",
                              typ_id=2, dry_run=dry_run)
            changed = True
        log.info(f"    [{action}] group '{grp_name}'  "
                 f"({len(member_ids)} members: "
                 f"{[f'WL-{primary_ip(w)}' for w in workloads if w['href'] in wl_obj_map and wl_obj_map[w['href']] in member_ids][:3]}...)")

        existing_members = existing_grp.get(grp_id, set())
        for mid in member_ids:
            if mid not in existing_members:
                fwo_upsert_objgrp(token, grp_id, mid, ic_id, dry_run)
                changed = True

    # Reconcile owner_network: remove entries no longer in PCE
    if not dry_run:
        import subprocess
        active_ips = {f"{primary_ip(wl)}/32" for wl in workloads if primary_ip(wl)}
        result = subprocess.run(
            ['sudo', '-u', 'postgres', 'psql', '-d', 'fworchdb', '-t', '-A',
             '-c', "SELECT ip FROM owner_network WHERE import_source='pce_sync' AND nw_type=10 AND is_deleted=false"],
            capture_output=True, text=True)
        for line in result.stdout.splitlines():
            stored_ip = line.strip()
            if stored_ip and stored_ip not in active_ips:
                subprocess.run(
                    ['sudo', '-u', 'postgres', 'psql', '-d', 'fworchdb',
                     '-c', f"UPDATE owner_network SET is_deleted=true WHERE ip='{stored_ip}' AND import_source='pce_sync'"],
                    capture_output=True)
                log.info(f"  Removed owner_network entry {stored_ip} (no longer in PCE)")
                changed = True

    if not dry_run and changed:
        fwo_gql(token, """mutation($mgm: Int!, $ic: bigint!) {
          update_rule(where: {mgm_id: {_eq: $mgm}}, _set: {rule_last_seen: $ic}) { affected_rows }
        }""", {"mgm": FWO_MGM_ID, "ic": ic_id})
        fwo_gql(token, """mutation($mgm: Int!, $ic: bigint!) {
          update_object(where: {mgm_id: {_eq: $mgm}, active: {_eq: true}},
                        _set: {obj_last_seen: $ic}) { affected_rows }
        }""", {"mgm": FWO_MGM_ID, "ic": ic_id})
        fwo_gql(token, """mutation($ic: bigint!) {
          update_objgrp(where: {active: {_eq: true}}, _set: {import_last_seen: $ic}) { affected_rows }
        }""", {"ic": ic_id})
        fwo_gql(token, """mutation($ic: bigint!) {
          update_objgrp_flat(where: {active: {_eq: true}}, _set: {import_last_seen: $ic}) { affected_rows }
        }""", {"ic": ic_id})
        _rebuild_latest_config(ic_id)
        log.info("  Import done ✓ (changes written)")
    else:
        if not dry_run and ic_id:
            fwo_gql(token, """mutation($ic: bigint!) {
              delete_import_control_by_pk(control_id: $ic) { control_id }
            }""", {"ic": ic_id})
        log.info("  Import done ✓ (no changes)")

# ── STEP 3: Export FWO rules → PCE rulesets ────────────────────────────────────

def get_or_update_pce_label_group(name, label_hrefs, existing_groups, dry_run):
    """Create or update a PCE label group (key=ar) and return its href."""
    body = {
        "name":       name,
        "key":        PCE_AR_KEY,
        "labels":     [{"href": h} for h in label_hrefs],
        "sub_groups": []
    }
    for grp in existing_groups:
        if grp["name"] == name:
            if not dry_run:
                pce_put(grp["href"], body)
            log.info(f"    Updated PCE label group '{name}' ({len(label_hrefs)} labels)")
            return grp["href"]
    if dry_run:
        log.info(f"    [DRY] Would create PCE label group '{name}'")
        return f"/orgs/{PCE_ORG}/sec_policy/draft/label_groups/dry_{name}"
    result = pce_post(f"/orgs/{PCE_ORG}/sec_policy/draft/label_groups", body)
    log.info(f"    Created PCE label group '{name}': {result['href']}")
    existing_groups.append(result)
    return result["href"]

def build_pce_actors(obj_list, objs_by_id, objgrp_members, existing_pce_groups, dry_run):
    """Map FWO rule objects to PCE actors.
    - Host object (typ=3): individual ar label → {"label": {"href": ...}}
    - Group object (typ=2): creates PCE label group from member ar labels
                            → {"label_group": {"href": ...}}
    """
    actors = []
    for entry in (obj_list or []):
        obj = entry.get("object")
        if not obj:
            continue
        typ = obj.get("obj_typ_id", 0)
        uid = (obj.get("obj_uid") or "").strip()

        if typ == 2:
            # Group: collect ar-label hrefs from all member objects
            grp_id       = obj["obj_id"]
            member_ids   = objgrp_members.get(grp_id, set())
            label_hrefs  = []
            for mid in member_ids:
                m = objs_by_id.get(mid)
                if m and (m.get("obj_uid") or "").startswith(f"/orgs/{PCE_ORG}/labels/"):
                    label_hrefs.append(m["obj_uid"])
            if not label_hrefs:
                log.warning(f"    Group '{obj.get('obj_name')}' has no resolvable members")
                continue
            grp_href = get_or_update_pce_label_group(
                obj["obj_name"], label_hrefs, existing_pce_groups, dry_run)
            actors.append({"label_group": {"href": grp_href}})

        elif uid.startswith(f"/orgs/{PCE_ORG}/labels/"):
            actors.append({"label": {"href": uid}})

        else:
            log.warning(f"    Object '{obj.get('obj_name')}' has no PCE uid — skipped")

    return actors or [{"actors": "ams"}]

def build_ingress_services(svc_list):
    if not svc_list:
        return [{"href": f"/orgs/{PCE_ORG}/sec_policy/draft/services/1"}]
    ports = []
    for s in svc_list:
        svc = s.get("service")
        if not svc:
            continue
        entry = {"proto": svc.get("ip_proto_id", 6)}
        if svc.get("svc_port") is not None:
            entry["port"] = svc["svc_port"]
        if svc.get("svc_port_end") not in (None, svc.get("svc_port")):
            entry["to_port"] = svc["svc_port_end"]
        ports.append(entry)
    return ports or [{"href": f"/orgs/{PCE_ORG}/sec_policy/draft/services/1"}]

def sync_export(token, dry_run):
    log.info("── STEP 3: FWO rules → PCE rulesets ─────────────────────────")

    rules = fwo_get_rules(token)
    log.info(f"  {len(rules)} active FWO rules")
    if not rules:
        log.info("  Nothing to export.")
        return

    objs_by_id      = {o["obj_id"]: o for o in fwo_get_objects(token)}
    objgrp_members  = fwo_get_objgrp_members(token)
    existing_rs     = pce_get(f"/orgs/{PCE_ORG}/sec_policy/draft/rule_sets",
                               {"max_results": 500})
    existing_pce_groups = pce_get(f"/orgs/{PCE_ORG}/sec_policy/draft/label_groups",
                                   {"max_results": 500})
    rs_by_name  = {rs["name"]: rs for rs in existing_rs}

    for rule in rules:
        rname   = rule.get("rule_name") or f"rule_{rule['rule_id']}"
        rs_name = RS_PREFIX + rname

        consumers = build_pce_actors(rule.get("rule_froms", []), objs_by_id,
                                     objgrp_members, existing_pce_groups, dry_run)
        providers = build_pce_actors(rule.get("rule_tos",   []), objs_by_id,
                                     objgrp_members, existing_pce_groups, dry_run)
        ingress   = build_ingress_services(rule.get("rule_services", []))

        rs_body = {
            "name":        rs_name,
            "enabled":     True,
            "description": rule.get("rule_comment") or "Created by FWO sync",
            "scopes":      [[]],
            "rules": [{
                "enabled":            True,
                "unscoped_consumers": True,
                "resolve_labels_as":  {"consumers": ["workloads"],
                                       "providers": ["workloads"]},
                "consumers":          consumers,
                "providers":          providers,
                "ingress_services":   ingress,
            }]
        }

        if rs_name in rs_by_name:
            if dry_run:
                log.info(f"  [DRY] Would update ruleset '{rs_name}'")
            else:
                pce_put(rs_by_name[rs_name]["href"], rs_body)
                log.info(f"  Updated  '{rs_name}'")
        else:
            if dry_run:
                log.info(f"  [DRY] Would create ruleset '{rs_name}'")
                log.info(f"    consumers={consumers}")
                log.info(f"    providers={providers}")
            else:
                result = pce_post(f"/orgs/{PCE_ORG}/sec_policy/draft/rule_sets", rs_body)
                log.info(f"  Created  '{rs_name}': {result['href']}")

    pce_provision(dry_run)


MODELLING_PREFIX = RS_PREFIX + "MODELLING_"

# Matches <ENV>-<APP>-<ROLE>  e.g.  PR-WEBAPP-WEB  DR-DB-DATA
ROLE_NAME_RE = re.compile(r'^([A-Z0-9]+)-([A-Z0-9]+)-([A-Z0-9]+)$')


def _pce_delete_ruleset(href, name, dry_run):
    if dry_run:
        log.info(f"  [DRY] Would delete PCE ruleset '{name}'")
    else:
        requests.delete(f"{PCE_BASE}{href}",
                        auth=HTTPBasicAuth(PCE_USER, PCE_PASS), verify=False)
        log.info(f"  Deleted PCE ruleset '{name}'")


def sync_modelling_nwgroups(token, workloads, dry_run):
    """Sync FWO modelling.nwgroup entries → PCE label groups (key=ar).
    Groups matching <ENV>-<APP>-<ROLE> also set env/app/role labels on member workloads."""
    log.info("── STEP 3b: FWO Modelling nwgroups → PCE label groups ───────")

    data = fwo_gql(token, """query {
      modelling_nwgroup(where: {app_id: {_eq: 3}, group_type: {_eq: 20}}) {
        id name is_deleted
        nwobject_nwgroups {
          owner_network { name ip }
        }
      }
    }""", {})
    all_groups = data.get("modelling_nwgroup", [])
    groups = [g for g in all_groups if not g["is_deleted"]]
    # All names ever known to FWO (active + deleted) — safe reconciliation boundary
    all_fwo_names = {g["name"] for g in all_groups}

    # Build IP → workload lookup for label assignment
    wl_by_ip = {primary_ip(wl): wl for wl in workloads if primary_ip(wl)}

    # Fetch current PCE ar-labels to map WL-name → label href
    all_labels = pce_get(f"/orgs/{PCE_ORG}/labels", {"max_results": 1000, "key": PCE_AR_KEY})
    label_by_name = {l["value"]: l["href"] for l in all_labels}

    existing_pce_groups = pce_get(f"/orgs/{PCE_ORG}/sec_policy/draft/label_groups",
                                   {"max_results": 500})
    pce_groups_by_name = {g["name"]: g for g in existing_pce_groups}

    # ── Conflict check: a workload must not appear in more than one named role ──
    # Build ip → [group_name, ...] for all named groups
    named_groups = [g for g in groups if parse_role_name(g["name"])]
    ip_to_named_groups: dict[str, list[str]] = {}
    for grp in named_groups:
        for entry in grp["nwobject_nwgroups"]:
            ip = str(entry["owner_network"]["ip"]).split("/")[0]
            ip_to_named_groups.setdefault(ip, []).append(grp["name"])

    # IPs assigned to more than one named role → label assignment would be ambiguous
    conflicting_ips: set[str] = set()
    for ip, grp_names in ip_to_named_groups.items():
        if len(grp_names) > 1:
            conflicting_ips.add(ip)
            log.warning(
                f"  CONFLICT: workload {ip} is member of multiple named roles "
                f"({', '.join(sorted(grp_names))}) — env/app/role labels will NOT be set on this workload"
            )

    provisioned = False
    for grp in groups:
        grp_name = grp["name"]
        # Map owner_network entries to PCE ar-label hrefs
        label_hrefs = []
        for entry in grp["nwobject_nwgroups"]:
            nw_name = entry["owner_network"]["name"]  # e.g. WL-172.24.50.161
            href = label_by_name.get(nw_name)
            if href:
                label_hrefs.append(href)
            else:
                log.warning(f"    No PCE ar-label for '{nw_name}' — skipped")

        if not label_hrefs:
            log.info(f"  Skip '{grp_name}' — no resolvable members")
            continue

        # Named groups: set env/app/role labels on member workloads (skip conflicting IPs)
        parsed = parse_role_name(grp_name)
        if parsed:
            env_val, app_val, role_val = parsed
            log.info(f"  Named role '{grp_name}' → env={env_val}, app={app_val}, role={role_val}")
            for entry in grp["nwobject_nwgroups"]:
                ip = str(entry["owner_network"]["ip"]).split("/")[0]
                if ip in conflicting_ips:
                    log.warning(f"    Skipping label assignment for {ip} (conflict)")
                    continue
                wl = wl_by_ip.get(ip)
                if wl:
                    _set_workload_role_labels(wl, env_val, app_val, role_val, dry_run)
                else:
                    log.warning(f"    No workload found for IP {ip}")

        if grp_name in pce_groups_by_name:
            existing = pce_groups_by_name[grp_name]
            existing_hrefs = sorted(m["href"] for m in existing.get("labels", []))
            if sorted(label_hrefs) != existing_hrefs:
                # key must NOT be sent in PUT — PCE returns 406
                update_body = {"name": grp_name,
                               "labels": [{"href": h} for h in label_hrefs],
                               "sub_groups": []}
                if not dry_run:
                    pce_put(existing["href"], update_body)
                log.info(f"  Updated  PCE label group '{grp_name}'")
            else:
                log.info(f"  OK       PCE label group '{grp_name}' (no change)")
            provisioned = True
        else:
            create_body = {"name": grp_name, "key": PCE_AR_KEY,
                           "labels": [{"href": h} for h in label_hrefs],
                           "sub_groups": []}
            if not dry_run:
                pce_post(f"/orgs/{PCE_ORG}/sec_policy/draft/label_groups", create_body)
            log.info(f"  Created  PCE label group '{grp_name}'")
            provisioned = True

    # Reconcile: only delete PCE label groups (key=ar) that came from FWO
    # (name appears in FWO history) but are no longer active there.
    # Groups created directly in PCE (name unknown to FWO) are never touched.
    active_names = {grp["name"] for grp in groups}
    ar_pce_groups = {name: g for name, g in pce_groups_by_name.items()
                     if g.get("key") == PCE_AR_KEY}
    for name, g in ar_pce_groups.items():
        if name in all_fwo_names and name not in active_names:
            _pce_delete_ruleset(g["href"], name, dry_run)
            provisioned = True

    if provisioned:
        pce_provision(dry_run)
    else:
        log.info("  Nothing new to provision")

    # ── Workload label cleanup ────────────────────────────────────────────────
    # IPs in a named group (non-conflicting) — these already have correct labels set above
    named_ips = {ip for ip in ip_to_named_groups if ip not in conflicting_ips}

    # Workloads no longer in any named role → strip env/app/role labels
    log.info("── Workload label cleanup ───────────────────────────────────")
    for wl in workloads:
        ip = primary_ip(wl)
        if ip in conflicting_ips:
            continue  # ambiguous assignment — don't touch
        if not ip or ip not in named_ips:
            _clear_workload_role_labels(wl, dry_run)

    # PCE labels for env/app/role that are no longer on any workload → delete
    used_label_hrefs = {
        l["href"]
        for wl in workloads
        for l in wl.get("labels", [])
        if l.get("key") in ("env", "app", "role")
    }
    for key in ("env", "app", "role"):
        for lbl in list(_get_labels_for_key(key)):
            if lbl["href"] not in used_label_hrefs:
                if dry_run:
                    log.info(f"  [DRY] Would delete unused PCE label {key}={lbl['value']}")
                else:
                    r = requests.delete(PCE_BASE + lbl["href"],
                                        auth=PCE_AUTH, verify=VERIFY_SSL)
                    if r.status_code in (200, 204):
                        log.info(f"  Deleted unused PCE label {key}={lbl['value']}")
                        _labels_by_key.pop(key, None)
                        _label_cache.pop((key, lbl["value"]), None)
                    elif r.status_code == 406:
                        log.info(f"  Label {key}={lbl['value']} still referenced "
                                 f"(ruleset/group) — kept")
                    else:
                        log.warning(f"  Delete label {key}={lbl['value']}: "
                                    f"{r.status_code} {r.text[:100]}")


def _actor_href(a):
    """Extract a stable string key from a PCE actor dict (label, label_group, or ip)."""
    if "label" in a:
        return a["label"].get("href", "")
    if "label_group" in a:
        return a["label_group"].get("href", "")
    return str(a)

def _svc_key(s):
    """Stable key for an ingress_service entry."""
    if "href" in s:
        return s["href"]
    return f"{s.get('proto')}:{s.get('port')}:{s.get('to_port','')}"

def _rs_signature(rs, rules):
    """Stable fingerprint of a ruleset for change detection."""
    parts = [rs.get("description", ""), str(rs.get("enabled", True))]
    for r in rules:
        parts.append(str(sorted(_actor_href(a) for a in r.get("consumers", []))))
        parts.append(str(sorted(_actor_href(a) for a in r.get("providers", []))))
        parts.append(str(sorted(_svc_key(s)   for s in r.get("ingress_services", []))))
    return "|".join(parts)


def sync_export_modelling(token, dry_run):
    """Export modelling.connection entries to PCE rulesets (FWO_MODELLING_<name>)."""
    log.info("── STEP 3c: FWO Modelling connections → PCE rulesets ────────")

    # Fetch ALL connections (active + removed) to handle deletions
    data = fwo_gql(token, """query {
      modelling_connection(where: {app_id: {_eq: 3}}) {
        id name reason removed
        source_nwobjects: nwobject_connections(where: {connection_field: {_eq: 1}}) {
          owner_network { name ip }
        }
        source_approles: nwgroup_connections(where: {connection_field: {_eq: 1}}) {
          nwgroup { name }
        }
        dest_nwobjects: nwobject_connections(where: {connection_field: {_eq: 2}}) {
          owner_network { name ip }
        }
        dest_approles: nwgroup_connections(where: {connection_field: {_eq: 2}}) {
          nwgroup { name }
        }
        service_connections {
          service { name port port_end proto_id }
        }
      }
    }""", {})

    all_conns = data.get("modelling_connection", [])
    active = [c for c in all_conns if not c["removed"]]
    removed = [c for c in all_conns if c["removed"]]
    log.info(f"  {len(active)} active, {len(removed)} removed modelling connections")

    existing_rs = pce_get(f"/orgs/{PCE_ORG}/sec_policy/draft/rule_sets", {"max_results": 500})
    existing_pce_groups = pce_get(f"/orgs/{PCE_ORG}/sec_policy/draft/label_groups",
                                   {"max_results": 500})
    rs_by_name = {rs["name"]: rs for rs in existing_rs}
    pce_groups_by_name = {g["name"]: g for g in existing_pce_groups}

    # PCE named services — build lookup by name and by port+proto
    pce_services_raw = pce_get(f"/orgs/{PCE_ORG}/sec_policy/draft/services", {"max_results": 500})
    pce_svc_by_name = {s["name"].lower(): s for s in pce_services_raw}
    # port+proto → service: match any service that contains this port/proto pair
    pce_svc_by_port = {}
    for s in pce_services_raw:
        for sp in s.get("service_ports", []):
            key = (sp.get("port"), sp.get("proto"))
            if key not in pce_svc_by_port:
                pce_svc_by_port[key] = s

    def _resolve_pce_service(svc_name, port, proto):
        """Return PCE service or None. Tries: exact → S-<name> → S-<name>-* (port-disambiguated) → port+proto."""
        name_l = (svc_name or "").strip().lower()
        if name_l and name_l in pce_svc_by_name:
            return pce_svc_by_name[name_l]
        if name_l:
            prefixed = f"s-{name_l}"
            if prefixed in pce_svc_by_name:
                return pce_svc_by_name[prefixed]
            # prefix match: s-ftp → [s-ftp-control, s-ftp-data]
            candidates = [v for k, v in pce_svc_by_name.items() if k.startswith(prefixed + "-")]
            if len(candidates) == 1:
                return candidates[0]
            # disambiguate by port when multiple candidates
            if candidates and port is not None and proto is not None:
                for c in candidates:
                    if any(sp.get("port") == port and sp.get("proto") == proto
                           for sp in c.get("service_ports", [])):
                        return c
        if port is not None and proto is not None:
            return pce_svc_by_port.get((port, proto))
        return None

    def _actors_with_env(nwobjects, approles):
        """Return (actors_without_env, env_segment_or_None).
        Named roles (<ENV>-<APP>-<ROLE>) → [app_label, role_label] actors, env returned separately.
        The caller decides whether env goes into scope or into actors.
        Other roles → ar-label-group actor (backward compat)."""
        actors = []
        env_seg = None
        for entry in approles:
            grp_name = entry["nwgroup"]["name"]
            parsed = parse_role_name(grp_name)
            if parsed:
                env, app, role = parsed
                app_href  = pce_ensure_label("app",  app,  dry_run)
                role_href = pce_ensure_label("role", role, dry_run)
                actors += [{"label": {"href": app_href}},
                           {"label": {"href": role_href}}]
                env_seg = env
                log.info(f"    Role '{grp_name}' → label actors app={app}, role={role}")
            elif grp_name in pce_groups_by_name:
                actors.append({"label_group": {"href": pce_groups_by_name[grp_name]["href"]}})
            else:
                log.warning(f"    PCE label group '{grp_name}' not found — skipped")
        for entry in nwobjects:
            ip = str(entry["owner_network"]["ip"]).split("/")[0]
            actors.append({"actors": ip})
        return actors or [{"actors": "ams"}], env_seg

    def _ingress(svc_connections):
        result = []
        for sc in svc_connections:
            s = sc["service"]
            matched = _resolve_pce_service(s.get("name"), s.get("port"), s.get("proto_id"))
            if matched:
                result.append({"href": matched["href"]})
                log.info(f"    Service '{s.get('name')}' → PCE '{matched['name']}' ({matched['href'].split('/')[-1]})")
            else:
                entry = {"proto": s["proto_id"]}
                if s.get("port") is not None:
                    entry["port"] = s["port"]
                if s.get("port_end") and s["port_end"] != s.get("port"):
                    entry["to_port"] = s["port_end"]
                result.append(entry)
                log.info(f"    Service '{s.get('name')}' → inline port {s.get('port')}/proto {s.get('proto_id')} (no PCE match)")
        return result or [{"href": f"/orgs/{PCE_ORG}/sec_policy/draft/services/1"}]

    provisioned = False

    # Soft-deleted connections (removed=true)
    for conn in removed:
        rs_name = MODELLING_PREFIX + (conn["name"] or f"conn_{conn['id']}")
        if rs_name in rs_by_name:
            _pce_delete_ruleset(rs_by_name[rs_name]["href"], rs_name, dry_run)
            provisioned = True

    # Reconcile: delete PCE rulesets with FWO_MODELLING_ prefix that no longer exist in FWO
    expected_rs_names = {MODELLING_PREFIX + (c["name"] or f"conn_{c['id']}") for c in active}
    for rs_name, rs in rs_by_name.items():
        if rs_name.startswith(MODELLING_PREFIX) and rs_name not in expected_rs_names:
            _pce_delete_ruleset(rs["href"], rs_name, dry_run)
            provisioned = True

    # Upsert active connections
    for conn in active:
        rs_name = MODELLING_PREFIX + (conn["name"] or f"conn_{conn['id']}")
        consumers, src_env = _actors_with_env(conn["source_nwobjects"], conn["source_approles"])
        providers, dst_env = _actors_with_env(conn["dest_nwobjects"],   conn["dest_approles"])
        ingress   = _ingress(conn["service_connections"])

        # Scope + env-in-actors logic:
        #  Same env on both sides → scope to that env; actors contain only app+role
        #  Different envs          → unscoped; env label prepended to each actor list
        if src_env and dst_env and src_env == dst_env:
            env_href = pce_ensure_label("env", src_env, dry_run)
            scopes   = [[{"label": {"href": env_href}}]]
            unscoped = False
            log.info(f"    Scoped ruleset: env={src_env}")
        else:
            scopes   = [[]]
            unscoped = True
            if src_env:
                src_env_href = pce_ensure_label("env", src_env, dry_run)
                consumers    = [{"label": {"href": src_env_href}}] + consumers
            if dst_env:
                dst_env_href = pce_ensure_label("env", dst_env, dry_run)
                providers    = [{"label": {"href": dst_env_href}}] + providers

        rs_body = {
            "name":        rs_name,
            "enabled":     True,
            "description": conn.get("reason") or "Created by FWO Modelling sync",
            "scopes":      scopes,
            "rules": [{
                "enabled":            True,
                "unscoped_consumers": unscoped,
                "resolve_labels_as":  {"consumers": ["workloads"], "providers": ["workloads"]},
                "consumers":          consumers,
                "providers":          providers,
                "ingress_services":   ingress,
            }]
        }

        if dry_run:
            log.info(f"  [DRY] Would upsert '{rs_name}'")
            provisioned = True
        elif rs_name in rs_by_name:
            existing_rs_obj = rs_by_name[rs_name]
            if _rs_signature(existing_rs_obj, existing_rs_obj.get("rules", [])) != \
               _rs_signature(rs_body, rs_body["rules"]):
                pce_put(existing_rs_obj["href"], rs_body)
                log.info(f"  Updated  '{rs_name}'")
                provisioned = True
            else:
                log.info(f"  OK       '{rs_name}' (no change)")
        else:
            result = pce_post(f"/orgs/{PCE_ORG}/sec_policy/draft/rule_sets", rs_body)
            log.info(f"  Created  '{rs_name}': {result['href']}")
            provisioned = True

    if provisioned:
        pce_provision(dry_run)


# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="FWO ↔ Illumio PCE bidirectional sync v3")
    parser.add_argument("--import-only", action="store_true")
    parser.add_argument("--export-only", action="store_true")
    parser.add_argument("--dry-run",     action="store_true")
    parser.add_argument("--debug",       action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("════════════════════════════════════════════════════════════")
    log.info("  FWO ↔ Illumio PCE  Sync  v3  (IP-label strategy)")
    if args.dry_run:
        log.info("  MODE: DRY RUN — no changes written")
    log.info("════════════════════════════════════════════════════════════")

    # Fetch PCE workloads once — full representation to get interfaces + labels
    log.info("Loading PCE workloads (managed + unmanaged)...")
    workloads = pce_get(f"/orgs/{PCE_ORG}/workloads", {"max_results": 500})
    log.info(f"  {len(workloads)} workloads found")

    token = fwo_token()
    log.info("FWO authenticated ✓")

    if not args.export_only:
        wl_to_ar = label_workloads_by_ip(workloads, args.dry_run)
        sync_import(token, workloads, wl_to_ar, args.dry_run)

    if not args.import_only:
        sync_modelling_nwgroups(token, workloads, args.dry_run)
        sync_export_modelling(token, args.dry_run)

    log.info("════════════════════════════════════════════════════════════")
    log.info("  Done ✓")
    log.info("════════════════════════════════════════════════════════════")

if __name__ == "__main__":
    main()
