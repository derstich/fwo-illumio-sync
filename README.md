# FWO ↔ Illumio PCE Sync

Bidirectional synchronisation between **[FireWall Orchestrator (FWO)](https://fwo.cactus.de/en/)** by [Cactus eSecurity](https://www.cactus.de) and the [Illumio Policy Compute Engine (PCE)](https://www.illumio.com).

---

## About FireWall Orchestrator

> *"Firewall management – central, transparent and secure"*

[FireWall Orchestrator](https://fwo.cactus.de/en/) is an **open-source firewall management platform** developed by [Cactus eSecurity](https://www.cactus.de) — **Made in Germany**.

It solves a core problem in heterogeneous enterprise environments: maintaining a consistent, auditable view across **firewalls from different manufacturers** in a single pane of glass. Key capabilities include:

- **Unified policy management** across diverse firewall platforms (Check Point, Fortinet, Palo Alto, Cisco, and more)
- **Change tracking & audit documentation** — every modification is recorded and traceable
- **Re-certification workflows** — structured review cycles for firewall rules
- **Modelling module** — design and validate application connectivity before deploying to production firewalls
- **API-first architecture** — built on GraphQL, Python, Ansible, and Apache; extensible for automation
- **Open source** with optional professional support — source code on [GitHub](https://github.com/CactuseSecurity/firewall-orchestrator)

FWO is actively maintained (v9.0+) and trusted by IT service providers, financial institutions, and online retailers managing large-scale firewall estates.

This integration uses FWO's **Modelling module** as the policy design surface, with Illumio PCE as the enforcement engine.

---

## ⚠️ Disclaimer / Important Notice

> **This integration is a transitional tool — not a target architecture.**
>
> Illumio is built around a **label-based micro-segmentation model**. Policies are expressed through labels (`role`, `env`, `app`, `loc`, `bu`) assigned to workloads. The native Illumio approach — described in this README as the **recommended path** — should be the goal for any deployment.
>
> This project exists to bridge a specific gap: organisations **migrating from a classical firewall-rule model** (managed in FWO) to Illumio segmentation. It allows security teams to continue working in their familiar FWO Modelling workflow while Illumio enforces the resulting policy.
>
> The AR label-group fallback (described at the end of this README) is provided **only for brownfield scenarios** where a full label-based migration is not yet possible. It should be replaced by native label-based policy as soon as feasible.

---

## Overview

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│   Illumio PCE               │        │   FireWall Orchestrator (FWO) │
│                             │        │                               │
│  Workloads with             │◄──────►│  Network Objects  WL-<IP>     │
│  env/app/role labels        │ import │                               │
│                             │        │                               │
│  Scoped Rulesets            │◄──────►│  Modelling App Roles          │
│  (label-based actors)       │ export │  <ENV>-<APP>-<ROLE>           │
└─────────────────────────────┘        └──────────────────────────────┘
         ▲
         │ PostgreSQL LISTEN/NOTIFY
         │ (instant trigger on Save)
         ▼
   fwo_sync_daemon.py
   (systemd service)
         +
   cron every 1 min
   (fwo_pce_sync.py)
```

---

## Policy Model: Label-Based (Recommended)

Illumio's native segmentation model assigns **labels** to workloads (`env`, `app`, `role`, `loc`, `bu`) and expresses policy in terms of those labels — not IP addresses. A rule that says *"env=prod, app=webapp, role=web can talk to env=prod, app=db, role=data on port 5432"* automatically follows workloads as they move, scale, or change IPs.

This integration maps FWO Modelling App Roles directly to this model using a naming convention.

### App Role Naming Convention: `<ENV>-<APP>-<ROLE>`

Name your FWO Modelling App Roles using three dash-separated segments:

```
prod-webapp-web     →  env=prod,  app=webapp,  role=web
prod-db-data        →  env=prod,  app=db,       role=data
dev-api-backend     →  env=dev,   app=api,      role=backend
```

- Segments are taken **exactly as written** (case-sensitive)
- Exactly 3 segments separated by `-`
- Each segment maps to one Illumio label key: `env` · `app` · `role`

> **Tip:** Pick a casing convention and stick to it. `prod` ≠ `Prod` ≠ `PROD` — inconsistent casing creates separate labels.

### What the sync does automatically

1. **Parses the name** into `(env, app, role)` segments
2. **Creates PCE labels** for each segment value if they don't exist yet
3. **Assigns labels to member workloads** — workloads in `prod-webapp-web` receive `env=prod`, `app=webapp`, `role=web`; existing `ar`, `bu`, `loc` labels are preserved
4. **Removes labels** when a workload is removed from a named App Role; deletes orphaned PCE labels
5. **Validates uniqueness** — a workload may only belong to one named App Role; the DB trigger blocks conflicting assignments at save time
6. **Creates scoped PCE rulesets** from Modelling connections:
   - Same env on both sides → ruleset scoped to `[[env=<ENV>]]`, actors are `[app=…, role=…]`
   - Different envs → global scope, env label prepended to each actor list
7. **Removes env/app/role labels** from workloads no longer in any named App Role and **deletes unused PCE labels** (graceful skip if still referenced by a ruleset)

### Connection → PCE Ruleset Example

FWO Modelling connection **`prod-webapp-web → prod-db-data`** on port 5432 produces:

```json
{
  "name": "webapp-to-db",
  "description": "[fwo-sync]",
  "scopes": [[{"label": {"href": "/orgs/1/labels/<env-prod>"}}]],
  "rules": [{
    "consumers":          [{"label": app=webapp}, {"label": role=web}],
    "providers":          [{"label": app=db},     {"label": role=data}],
    "ingress_services":   [{"href": ".../S-POSTGRESQL"}],
    "unscoped_consumers": false
  }]
}
```

Cross-environment connection **`prod-webapp-web → dev-db-data`**:

```json
{
  "name": "webapp-prod-to-db-dev",
  "scopes": [[]],
  "rules": [{
    "consumers":          [{"label": env=prod}, {"label": app=webapp}, {"label": role=web}],
    "providers":          [{"label": env=dev},  {"label": app=db},     {"label": role=data}],
    "unscoped_consumers": true
  }]
}
```

### Special Actors

| FWO Modelling object | PCE actor |
|---|---|
| App Role named `ALL_WORKLOADS` | `{"actors": "ams"}` — all workloads |
| Network object with IP `0.0.0.0` | `{"ip_list": ...}` — PCE "Any (0.0.0.0/0 and ::/0)" |

### PCE Label Hygiene

**Greenfield deployment:**
> Delete all pre-existing `env`, `app`, and `role` labels before the first sync. The sync creates exactly the labels it needs, derived from App Role names.

**Brownfield — existing labels:**
> Audit `env`, `app`, and `role` labels before enabling named App Roles. Remove duplicates (`prod` vs `PROD` vs `Production` → pick one). Name your App Role segments to match the **exact value** of your existing PCE labels.

```bash
# Review existing env/app/role labels
curl -su "api_<key>:<secret>" \
  "https://<pce>:8443/api/v2/orgs/1/labels?max_results=500" \
  | jq '[.[] | select(.key == "env" or .key == "app" or .key == "role") | {key, value}]'
```

---

## Policy Model: AR Label-Groups (Brownfield Fallback Only)

> **Use this approach only if a label-based migration is not yet feasible.** It bypasses Illumio's native workload identity model and should be treated as a temporary measure.

In this mode, FWO App Roles with names that do **not** match `<ENV>-<APP>-<ROLE>` (e.g. `AR9904567-001`) are synchronised as PCE **label groups** using the `ar` label key:

- Each PCE workload receives a unique `ar=WL-<IP>` label as an identity anchor
- App Role members are collected as ar-label hrefs → PCE label group `AR9904567-001` (key=ar)
- Connections referencing these App Roles produce PCE rulesets with `{"label_group": ...}` actors

This is fully backward-compatible. Named (`<ENV>-<APP>-<ROLE>`) and AR-style App Roles can coexist in the same FWO Modelling application.

### Limitations of the AR approach

1. **IP-centric identity** — the `ar=WL-<IP>` label ties workload identity to an IP address. Illumio's strength (identity independent of IP) is not used.
2. **No label inheritance** — workloads do not receive meaningful `env`/`app`/`role` labels; Illumio visibility and policy tooling is degraded.
3. **Unscoped rulesets** — rules apply globally, not scoped to an environment or application.
4. **FWO is authoritative** — direct changes to sync-managed rulesets in the PCE UI are overwritten on the next sync.

---

## Prerequisites

| Component | Version tested |
|-----------|---------------|
| FireWall Orchestrator | 8.x |
| Illumio PCE | 23.x / 24.x |
| Python | 3.10+ |
| psycopg2 | any recent |
| PostgreSQL | 14+ (FWO internal DB `fworchdb`) |

Python packages:
```bash
pip3 install requests psycopg2-binary
```

---

## Repository Structure

```
fwo-illumio-sync/
├── README.md
├── fwo_pce_sync.py          # Main sync script (cron)
├── fwo_sync_daemon.py       # PostgreSQL NOTIFY daemon (systemd)
├── sql/
│   ├── triggers.sql         # DB triggers: instant sync + uniqueness enforcement
│   └── initial_objects.sql  # One-time setup: ANY, ALL_WORKLOADS, ALL_SERVICES
└── systemd/
    └── fwo-sync-daemon.service
```

---

## Installation

### 1. Copy scripts to FWO server

```bash
scp fwo_pce_sync.py   user@fwo-server:/usr/local/fworch/bin/
scp fwo_sync_daemon.py user@fwo-server:/usr/local/fworch/bin/
chmod +x /usr/local/fworch/bin/fwo_pce_sync.py
chmod +x /usr/local/fworch/bin/fwo_sync_daemon.py
```

### 2. Configure credentials

Edit the `Config` section at the top of `fwo_pce_sync.py`:

```python
FWO_GRAPHQL   = "https://localhost:9443/api/v1/graphql"
FWO_AUTH_URL  = "http://localhost:8880/api/AuthenticationToken/Get"
FWO_USER      = "admin"
FWO_PASS      = "<fwo-admin-password>"
FWO_MGM_ID    = 7        # Management ID of your Illumio device in FWO
FWO_OWNER_ID  = 3        # owner_id in FWO Modelling (owner_network table)

PCE_BASE      = "https://<pce-hostname>:8443/api/v2"
PCE_ORG       = 1
PCE_USER      = "api_<key-id>"
PCE_PASS      = "<api-secret>"
```

To find `FWO_MGM_ID` and `FWO_OWNER_ID`:
```bash
sudo -u postgres psql fworchdb -c "SELECT id, name FROM management;"
sudo -u postgres psql fworchdb -c "SELECT id, name FROM owner;"
```

### 3. Install PostgreSQL triggers

```bash
sudo -u postgres psql fworchdb -f sql/triggers.sql
```

This installs:
- **NOTIFY triggers** — instant sync on every Modelling save
- **Uniqueness trigger** — blocks assigning a workload to multiple named App Roles at DB level

### 3b. Create initial Modelling objects

```bash
sudo -u postgres psql fworchdb -f sql/initial_objects.sql
```

This creates three reserved objects used by the sync for special PCE actors:

| Object | Type | PCE mapping |
|--------|------|-------------|
| `ANY` (`0.0.0.0/32`) | Network object | `Any (0.0.0.0/0 and ::/0)` IP list |
| `ALL_WORKLOADS` | App Role (with ANY as member) | `{"actors": "ams"}` — all workloads |
| `ALL_SERVICES` | Service (no port/proto) | PCE `All Services` |

> If your `app_id` or `owner_id` differ from the defaults (both `3`), edit the `\set` lines at the top of `sql/initial_objects.sql` before running.

### 4. Install and start the daemon

```bash
sudo cp systemd/fwo-sync-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable fwo-sync-daemon
sudo systemctl start fwo-sync-daemon
sudo systemctl status fwo-sync-daemon
```

### 5. Set up the cron job (1-minute full sync)

```bash
sudo crontab -e
# Add:
* * * * * /usr/bin/python3 /usr/local/fworch/bin/fwo_pce_sync.py >> /var/log/fwo_pce_sync.log 2>&1
```

### 6. Run initial import

```bash
sudo python3 /usr/local/fworch/bin/fwo_pce_sync.py
```

---

## FWO Modelling Setup

### Network Areas (optional but recommended)

Network Areas define IP subnets so FWO can automatically suggest which App Servers belong to an App Role. Create them via SQL if not present in the UI:

```sql
-- Create a Network Area for each subnet
INSERT INTO modelling.nwgroup (name, id_string, creator, group_type, is_deleted)
VALUES ('NET-192.168.10.0/24', 'NET-192.168.10.0/24', 'admin', 23, false);

-- Add IP range entry (start/end as /32 host addresses)
INSERT INTO owner_network (name, ip, ip_end, nw_type, import_source, is_deleted)
VALUES ('NET-192.168.10.0/24', '192.168.10.0/32', '192.168.10.255/32', 11, 'pce_sync', false)
RETURNING id;

-- Link area to its IP range (use returned id)
INSERT INTO modelling.nwobject_nwgroup (nwobject_id, nwgroup_id)
VALUES (<returned-id>, <area-id>);
```

### FWO Services

Create standard services in FWO Modelling (Administration → Services). The sync resolves service names to PCE named services in this order:

1. Exact name match (case-insensitive): `HTTP` → PCE `HTTP`
2. `S-` prefix match: `HTTP` → PCE `S-HTTP`
3. Partial prefix + port disambiguation: `FTP` + port 21 → PCE `S-FTP-CONTROL`
4. Port + protocol fallback: port 443/TCP → PCE `S-HTTPS`
5. Inline port definition (no PCE service found)

---

## PCE Requirements

- API user with **Read/Write** access to workloads, labels, label groups, rule sets, IP lists, services
- Workloads (managed and unmanaged) must be registered in the PCE
- The **"Any (0.0.0.0/0 and ::/0)"** IP list must exist in the PCE if you use `0.0.0.0` network objects in FWO connections

---

## Change Detection

The sync is designed to be idempotent and efficient:

| Component | Change detection |
|-----------|-----------------|
| PCE ar-labels | Compares current label href on workload |
| PCE env/app/role labels | Set from App Role name; removed when workload leaves named role |
| FWO host objects | Skips if `obj_name` and `obj_uid` unchanged |
| FWO group objects | Skips if `obj_uid` (PCE label href) unchanged |
| PCE label groups | Compares sorted member hrefs |
| PCE rulesets | Compares consumer/provider/service hrefs via signature |
| owner_network (App Servers) | Always ensures `is_deleted=false` for active workloads |

If nothing changed, no `import_control` entry is written, `latest_config` is not rebuilt, and no PCE provision is triggered.

---

## Caveats & Limitations

1. **Label-based approach requires naming discipline** — App Role names drive PCE label values directly. Renaming an App Role is a breaking change; the old labels will be removed from workloads and the old ruleset deleted.

2. **FWO is authoritative** — direct changes to sync-managed rulesets in the PCE UI are overwritten on the next sync.

3. **AR label groups (legacy)** — groups with `key=ar` whose names appear in FWO history are managed exclusively by the sync. Do not rename them in the PCE. Manually created `key=ar` groups with names unknown to FWO are never touched.

4. **Service name mapping is heuristic** — the FWO→PCE service name resolution uses name-based matching with fallback. Ambiguous names (e.g. `FTP` matching both `S-FTP-CONTROL` and `S-FTP-DATA`) require port disambiguation or exact naming.

5. **No multi-tenancy** — the sync is scoped to a single FWO management (`FWO_MGM_ID`) and a single PCE organisation (`PCE_ORG`).

6. **Unpair/re-pair cycle** — when a workload is unpaired from PCE and re-registered, the sync restores its FWO objects on the next run. There may be a brief window (up to 1 minute) where the object shows as deleted in FWO.

---

## Troubleshooting

**Workload appears with `!` in FWO monitoring**
→ The `owner_network` entry may be `is_deleted=true`. Fix:
```bash
sudo -u postgres psql fworchdb -c \
  "UPDATE owner_network SET is_deleted=false WHERE ip='<ip>/32' AND import_source='pce_sync';"
```

**Workload blocked from joining a named App Role**
→ The uniqueness trigger fired — the workload is already in another named role. Check:
```bash
sudo -u postgres psql fworchdb -c \
  "SELECT g.name FROM modelling.nwgroup g
   JOIN modelling.nwobject_nwgroup og ON og.nwgroup_id = g.id
   JOIN owner_network n ON n.id = og.nwobject_id
   WHERE n.ip = '<ip>/32' AND g.name ~ '^[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+$';"
```

**PCE label group deleted unexpectedly**
→ Check if the group name exists in FWO nwgroup history:
```bash
sudo -u postgres psql fworchdb -c \
  "SELECT id, name, is_deleted FROM modelling.nwgroup WHERE name='<group-name>';"
```

**Daemon not triggering on Save**
→ Check triggers are installed and daemon is running:
```bash
sudo -u postgres psql fworchdb -c \
  "SELECT trigger_name, event_object_table FROM information_schema.triggers WHERE trigger_name LIKE 'trg_%';"
sudo systemctl status fwo-sync-daemon
sudo journalctl -u fwo-sync-daemon -n 30
```

**`Any (0.0.0.0/0 and ::/0)` IP list not found**
→ Create it in the PCE under *Policy Objects → IP Lists → New*, add range `0.0.0.0/0`.

---

## License

MIT — use at your own risk. See [Disclaimer](#️-disclaimer--important-notice).
