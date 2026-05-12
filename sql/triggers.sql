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

-- Verify installation
SELECT trigger_name, event_object_schema, event_object_table, event_manipulation
FROM information_schema.triggers
WHERE trigger_name LIKE 'trg_notify%'
ORDER BY event_object_table, event_manipulation;
