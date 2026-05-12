-- FWO Modelling — Initial Objects for PCE Sync
-- ==============================================
-- Run once after installation to create the three reserved objects
-- used by the sync for special PCE actors.
--
-- Usage:
--   sudo -u postgres psql fworchdb -f sql/initial_objects.sql
--
-- Prerequisites:
--   - FWO Modelling application must exist (app_id=3 by default)
--   - FWO_OWNER_ID must match your owner (owner_id=3 by default)
--   - Adjust APP_ID / OWNER_ID below if your values differ

-- ── Configuration ──────────────────────────────────────────────────────────────
\set APP_ID   3
\set OWNER_ID 3

-- ── 1. ANY network object (0.0.0.0) ───────────────────────────────────────────
-- Represents "Any (0.0.0.0/0 and ::/0)" traffic in FWO connections.
-- import_source='manual' ensures the sync never deletes this entry.
INSERT INTO owner_network (name, ip, ip_end, nw_type, owner_id, import_source, is_deleted)
SELECT 'ANY', '0.0.0.0/32', '0.0.0.0/32', 10, :OWNER_ID, 'manual', false
WHERE NOT EXISTS (SELECT 1 FROM owner_network WHERE ip = '0.0.0.0/32');

-- ── 2. ALL_WORKLOADS App Role ──────────────────────────────────────────────────
-- Reserved App Role name — maps to PCE {"actors": "ams"} (all workloads).
-- ANY is added as its only member so FWO does not show a validation warning.
DO $$
DECLARE
  v_any_id  bigint;
  v_grp_id  bigint;
BEGIN
  SELECT id INTO v_any_id FROM owner_network WHERE ip = '0.0.0.0/32';

  INSERT INTO modelling.nwgroup (app_id, name, id_string, group_type, is_deleted, creator)
  SELECT :'APP_ID'::int, 'ALL_WORKLOADS', 'ALL_WORKLOADS', 20, false, 'admin'
  WHERE NOT EXISTS (SELECT 1 FROM modelling.nwgroup WHERE name = 'ALL_WORKLOADS')
  RETURNING id INTO v_grp_id;

  IF v_grp_id IS NULL THEN
    SELECT id INTO v_grp_id FROM modelling.nwgroup WHERE name = 'ALL_WORKLOADS';
  END IF;

  INSERT INTO modelling.nwobject_nwgroup (nwobject_id, nwgroup_id)
  SELECT v_any_id, v_grp_id
  WHERE NOT EXISTS (
    SELECT 1 FROM modelling.nwobject_nwgroup
    WHERE nwobject_id = v_any_id AND nwgroup_id = v_grp_id
  );
END;
$$;

-- ── 3. ALL_SERVICES service ────────────────────────────────────────────────────
-- Reserved service name — maps to PCE "All Services" (no port/protocol filter).
-- is_global=true makes it available in all FWO Modelling applications.
INSERT INTO modelling.service (app_id, name, is_global, port, port_end, proto_id)
SELECT NULL, 'ALL_SERVICES', true, NULL, NULL, NULL
WHERE NOT EXISTS (SELECT 1 FROM modelling.service WHERE name = 'ALL_SERVICES');

-- ── Verify ─────────────────────────────────────────────────────────────────────
SELECT 'owner_network' AS "table", name, ip::text AS detail
FROM owner_network WHERE ip = '0.0.0.0/32'
UNION ALL
SELECT 'nwgroup', name, 'group_type=' || group_type
FROM modelling.nwgroup WHERE name = 'ALL_WORKLOADS'
UNION ALL
SELECT 'service', name, 'port=ALL proto=ALL'
FROM modelling.service WHERE name = 'ALL_SERVICES';
