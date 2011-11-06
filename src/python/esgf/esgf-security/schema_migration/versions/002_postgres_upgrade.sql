--
-- Upgrading security schema to have an additional field to the "user"
-- table to support end user notification.
--

SET search_path = esgf_security, pg_catalog;

--
-- Upgrade to increase standard_name size
--

ALTER TABLE user
  ADD COLUMN notification_code integer DEFAULT 0;


--
-- Name: notification_types; Type: TABLE; Schema: esgf_security; Owner: -; Tablespace: 
--

CREATE TABLE notification_types (
    code integer NOT NULL,
    name character varying(100) NOT NULL,
    description text NOT NULL

--
-- Initialize notification types
--
 
INSERT INTO esgf_security.notification_types (code, name, description) VALUES (1,'email','Email Notification');

--
-- PostgreSQL database dump complete
-- Reset search path to public, so that esgf_migrate_version can be updated.
--

SET search_path = public, pg_catalog;
