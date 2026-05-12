-- FWO Modelling → PCE Instant Sync Triggers
-- ============================================
-- Install these triggers on the FWO PostgreSQL database (fworchdb) so that
-- any change in the Modelling module immediately notifies the sync daemon.
--
-- Usage:
--   sudo -u postgres psql fworchdb -f sql/triggers.sql

CREATE OR REPLACE FUNCTION modelling_notify_change()
RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('fwo_modelling_changed', '');
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Trigger: modelling.connection (policy connections)
DROP TRIGGER IF EXISTS trg_notify_connection ON modelling.connection;
CREATE TRIGGER trg_notify_connection
  AFTER INSERT OR UPDATE OR DELETE ON modelling.connection
  FOR EACH STATEMENT EXECUTE FUNCTION modelling_notify_change();

-- Trigger: modelling.nwgroup (App Roles / label groups)
DROP TRIGGER IF EXISTS trg_notify_nwgroup ON modelling.nwgroup;
CREATE TRIGGER trg_notify_nwgroup
  AFTER INSERT OR UPDATE OR DELETE ON modelling.nwgroup
  FOR EACH STATEMENT EXECUTE FUNCTION modelling_notify_change();

-- Trigger: modelling.nwobject_nwgroup (group memberships)
DROP TRIGGER IF EXISTS trg_notify_nwobject_nwgroup ON modelling.nwobject_nwgroup;
CREATE TRIGGER trg_notify_nwobject_nwgroup
  AFTER INSERT OR UPDATE OR DELETE ON modelling.nwobject_nwgroup
  FOR EACH STATEMENT EXECUTE FUNCTION modelling_notify_change();

-- ── Uniqueness constraint: one <ENV>-<APP>-<ROLE> named role per workload ────────
-- Prevents a workload from being added to a second named App Role via the FWO UI.
-- Named roles are identified by the pattern  ^[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+$
-- (e.g. PR-WEBAPP-WEB). Non-matching groups (e.g. AR9904567-001) are unaffected.

CREATE OR REPLACE FUNCTION modelling_check_unique_named_role()
RETURNS trigger AS $$
DECLARE
  target_name   text;
  conflict_name text;
BEGIN
  -- Is the target group a named role?
  SELECT name INTO target_name
  FROM modelling.nwgroup
  WHERE id          = NEW.nwgroup_id
    AND group_type  = 20
    AND is_deleted  = false
    AND name        ~ '^[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+$';

  IF NOT FOUND THEN
    RETURN NEW;  -- not a named role, no restriction
  END IF;

  -- Is this workload already in a different named role?
  SELECT g.name INTO conflict_name
  FROM modelling.nwobject_nwgroup og
  JOIN modelling.nwgroup g ON g.id = og.nwgroup_id
  WHERE og.nwobject_id = NEW.nwobject_id
    AND og.nwgroup_id != NEW.nwgroup_id
    AND g.group_type   = 20
    AND g.is_deleted   = false
    AND g.name         ~ '^[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+$';

  IF FOUND THEN
    RAISE EXCEPTION
      'Workload is already assigned to named role "%" — '
      'a workload may only belong to one <ENV>-<APP>-<ROLE> App Role at a time.',
      conflict_name;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_check_unique_named_role ON modelling.nwobject_nwgroup;
CREATE TRIGGER trg_check_unique_named_role
  BEFORE INSERT ON modelling.nwobject_nwgroup
  FOR EACH ROW EXECUTE FUNCTION modelling_check_unique_named_role();

-- Verify installation
SELECT trigger_name, event_object_schema, event_object_table, event_manipulation
FROM information_schema.triggers
WHERE trigger_name LIKE 'trg_%'
ORDER BY event_object_table, event_manipulation;
