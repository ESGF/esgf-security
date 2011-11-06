--
-- Downgrading security schema to remove field from the "user"
-- table that was put there to support end user notification.
--

SET search_path = esgf_security, pg_catalog;

ALTER TABLE user 
DROP COLUMN notification_code RESTRICT;

--
-- PostgreSQL database dump complete
-- Reset search path to public, so that esgf_migrate_version can be updated.
--

SET search_path = public, pg_catalog;
