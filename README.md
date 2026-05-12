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

This integration leverages FWO's **Modelling module** as the policy design surface, with Illumio PCE as the enforcement engine.

---

## ⚠️ Disclaimer / Important Notice

> **This integration is a transitional workaround — not a target architecture.**
>
> Illumio is built around a **label-based micro-segmentation model**. Policies are expressed through labels (`role`, `env`, `app`, `loc`, `bu`) assigned to workloads, not through traditional IP-address-based firewall rules. The native Illumio approach should be the goal for any greenfield deployment or mature migration.
>
> This project exists to bridge a specific gap: organisations that are **migrating from a classical firewall-rule model** (managed in FWO) to Illumio segmentation, and need a **temporary, consistent mapping** between the two worlds during the transition period. It allows security teams to continue working in their familiar FWO modelling workflow while Illumio enforces the resulting policy.
>
> **This approach has inherent limitations** (see [Caveats](#caveats--limitations)) and should be replaced by native Illumio label-based policy design as soon as the migration is complete.

---

## Overview

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│   Illumio PCE               │        │   FireWall Orchestrator (FWO) │
│                             │        │                               │
│  Workloads (managed +       │◄──────►│  Network Objects  WL-<IP>     │
│  unmanaged) with labels     │ import │  Object Groups    PCE_*       │
│                             │        │                               │
│  Label Groups (ar=*)        │◄──────►│  Modelling nwgroups  AR*      │
│  Rulesets FWO_MODELLING_*   │ export │  Modelling connections        │
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

### What the sync does

**Import (PCE → FWO)**
- Creates/updates FWO host objects `WL-<IP>` for every PCE workload (managed + unmanaged)
- Assigns PCE label `ar=WL-<IP>` to each workload as a stable identity anchor
- Creates FWO object groups `PCE_<key>_<value>` from PCE labels (`role`, `env`, `app`, `bu`, `loc`)
- Populates `owner_network` (FWO Modelling App Servers) so workloads are selectable in the Modelling module
- Reconciles: workloads removed from PCE are marked as deleted in FWO

**Export (FWO → PCE)**
- Syncs FWO Modelling **nwgroups** (App Roles) → PCE label groups (`key=ar`)
- Syncs FWO Modelling **connections** → PCE rulesets `FWO_MODELLING_<name>`
- Resolves service names: FWO service name matched against PCE named services (e.g. `HTTP` → `S-HTTP`)
- Reconciles: connections/groups deleted in FWO are removed from PCE
- **Only writes when data actually changed** — no unnecessary PCE provisions per cron cycle

**Instant trigger**
- PostgreSQL `LISTEN/NOTIFY` triggers fire on every `INSERT/UPDATE/DELETE` on the modelling tables
- `fwo_sync_daemon.py` picks up the notification with a 2-second debounce and immediately runs `--export-only`
- This means PCE is updated within seconds of pressing **Save** in FWO Modelling

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
│   └── triggers.sql         # DB triggers for instant sync
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
FWO_AUTH_URL  = "http://127.0.0.1:8880/api/AuthenticationToken/Get"
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

### 3. Install PostgreSQL NOTIFY triggers

```bash
sudo -u postgres psql fworchdb -f sql/triggers.sql
```

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

## Label-Based Policy (Recommended)

App Roles in FWO Modelling can follow the `<ENV>-<APP>-<ROLE>` naming convention to automatically drive PCE label assignment and produce scoped, label-based rulesets — the native Illumio approach.

### PCE Label Hygiene (important)

The sync derives PCE labels **exactly** from App Role name segments — case-sensitive, no transformation. `DeV-APP03-web` produces `env=DeV`, `app=APP03`, `role=web`. If a label with that exact value does not exist in the PCE it is created automatically.

The App Role name in FWO is the single source of truth for label values. Inconsistent casing across groups creates separate labels (`dev` ≠ `Dev` ≠ `DEV`) — so pick a convention and stick to it.

**Greenfield deployment:**
> Delete all pre-existing `env`, `app`, and `role` labels before running the sync. The sync will create exactly the labels it needs, derived from App Role names.

**Brownfield / existing label infrastructure:**
> Audit all `env`, `app`, and `role` labels before enabling named App Roles:
> - Remove duplicates and aliases (`prod`, `PROD`, `Production` → pick one)
> - Name your App Role segments to match the exact casing of existing PCE labels
> - Example: if your PCE uses `env=Production`, name the App Role `Production-APP01-web`

```bash
# List all env/app/role labels in the PCE to review
curl -su "api_<key>:<secret>" \
  "https://<pce>:8443/api/v2/orgs/1/labels?max_results=500" \
  | jq '[.[] | select(.key == "env" or .key == "app" or .key == "role") | {key, value}]'
```

---

### Naming Convention

```
PR-WEBAPP-WEB     →  env=PR,  app=WEBAPP,  role=WEB
DR-DB-DATA        →  env=DR,  app=DB,      role=DATA
PROD-API-BACKEND  →  env=PROD, app=API,    role=BACKEND
```

- Segments are uppercase alphanumeric, separated by `-`
- At least one character per segment
- Exactly 3 segments: Environment · Application · Role

### What the sync does for named App Roles

1. **Parses the name** into `(env, app, role)` components
2. **Creates PCE labels** `env=<ENV>`, `app=<APP>`, `role=<ROLE>` if they don't exist
3. **Sets those labels on member workloads** — workloads assigned to `PR-WEBAPP-WEB` receive `env=PR`, `app=WEBAPP`, `role=WEB` (existing `ar`, `bu`, `loc` labels are preserved)
4. **Connections between named roles produce scoped rulesets**:
   - If source and destination share the same `env` → ruleset scope `[[env=<ENV>]]`, consumers not unscoped
   - Otherwise → global scope `[[]]`
   - Actors are PCE label refs (`app=…`, `role=…`) — not ar-label-groups

### Example

FWO Modelling connection `PR-WEBAPP-WEB → PR-DB-DATA` produces:

```json
{
  "name": "FWO_MODELLING_WEB-TO-DB",
  "scopes": [[{"label": {"href": "/orgs/1/labels/<env-PR>"}}]],
  "rules": [{
    "consumers":        [{"label": app=WEBAPP}, {"label": role=WEB}],
    "providers":        [{"label": app=DB},     {"label": role=DATA}],
    "unscoped_consumers": false
  }]
}
```

### Backward Compatibility

App Roles whose names do **not** match the `<ENV>-<APP>-<ROLE>` pattern (e.g. `AR9904567-001`) continue to use the existing ar-label-group approach unchanged. Both styles can coexist in the same FWO Modelling application.

---

## FWO Modelling Setup

After the initial import, the following FWO Modelling objects are needed:

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

- API user with **Read/Write** access to workloads, labels, label groups, rule sets, services
- Workloads (managed and unmanaged) must be registered in the PCE
- Labels for segmentation (`role`, `env`, `app`, `bu`, `loc`) should already be assigned — the sync reads them to build FWO object groups

---

## Change Detection

The sync is designed to be idempotent and efficient:

| Component | Change detection |
|-----------|-----------------|
| PCE ar-labels | Compares current label href on workload |
| FWO host objects | Skips if `obj_name` and `obj_uid` unchanged |
| FWO group objects | Skips if `obj_uid` (PCE label href) unchanged |
| PCE label groups | Compares sorted member hrefs |
| PCE rulesets | Compares consumer/provider/service hrefs |
| owner_network (App Servers) | Always ensures `is_deleted=false` for active workloads |

If nothing changed, no `import_control` entry is written, `latest_config` is not rebuilt, and no PCE provision is triggered.

---

## Caveats & Limitations

1. **IP-centric, not label-centric**: This sync uses IP addresses as the primary identity (`ar=WL-<IP>`). Illumio's strength is workload identity independent of IP. This approach loses that benefit.

2. **FWO as authoritative source**: Policy changes must be made in FWO Modelling. Direct changes to `FWO_MODELLING_*` rulesets in the PCE UI will be overwritten on the next sync.

3. **PCE label groups created by sync**: Label groups with `key=ar` whose names appear in FWO history are managed exclusively by the sync. Do not rename them in the PCE.

4. **Manually created PCE label groups are preserved**: The reconciliation only deletes PCE label groups that are known to FWO (appeared in FWO nwgroup history). Groups created directly in PCE with `key=ar` and a name not known to FWO will not be touched.

5. **Service name mapping is heuristic**: The FWO→PCE service name resolution uses name-based matching with fallback. Ambiguous names (e.g. `FTP` matching both `S-FTP-CONTROL` and `S-FTP-DATA`) require port disambiguation or exact naming.

6. **No multi-tenancy**: The sync is scoped to a single FWO management (`FWO_MGM_ID`) and a single PCE organisation (`PCE_ORG`).

7. **Unpair/re-pair cycle**: When a workload is unpaired from PCE and re-registered, the sync automatically restores its FWO objects and `owner_network` entry on the next run. There may be a brief window (up to 1 minute) where the object shows as deleted in FWO.

---

## Troubleshooting

**Workload appears with `!` in FWO monitoring**
→ The `owner_network` entry may be `is_deleted=true`. Fix:
```bash
sudo -u postgres psql fworchdb -c \
  "UPDATE owner_network SET is_deleted=false WHERE ip='<ip>/32' AND import_source='pce_sync';"
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
  "SELECT trigger_name, event_object_table FROM information_schema.triggers WHERE trigger_name LIKE 'trg_notify%';"
sudo systemctl status fwo-sync-daemon
sudo journalctl -u fwo-sync-daemon -n 30
```

**HTTP 406 on PCE label group update**
→ The `key` field must not be included in PUT requests to the PCE. This is handled automatically — do not add `key` to update bodies.

---

## License

MIT — use at your own risk. See [Disclaimer](#️-disclaimer--important-notice).
