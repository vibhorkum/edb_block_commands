/* set-user--1.4.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION edb_switch_user" to load this file. \quit

CREATE FUNCTION edb_switch_user(text)
RETURNS text
AS 'MODULE_PATHNAME', 'edb_switch_user'
LANGUAGE C;

CREATE FUNCTION edb_switch_user(text, text)
RETURNS text
AS 'MODULE_PATHNAME', 'edb_switch_user'
LANGUAGE C STRICT;

REVOKE EXECUTE ON FUNCTION edb_switch_user(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION edb_switch_user(text, text) FROM PUBLIC;

CREATE FUNCTION reset_edb_switch_user()
RETURNS text
AS 'MODULE_PATHNAME', 'edb_switch_user'
LANGUAGE C;

CREATE FUNCTION reset_edb_switch_user(text)
RETURNS text
AS 'MODULE_PATHNAME', 'edb_switch_user'
LANGUAGE C STRICT;

GRANT EXECUTE ON FUNCTION reset_edb_switch_user() TO PUBLIC;
GRANT EXECUTE ON FUNCTION reset_edb_switch_user(text) TO PUBLIC;

/* New functions in 1.1 (now 1.4) begin here */

CREATE FUNCTION edb_switch_user_u(text)
RETURNS text
AS 'MODULE_PATHNAME', 'edb_switch_user'
LANGUAGE C STRICT;

REVOKE EXECUTE ON FUNCTION edb_switch_user_u(text) FROM PUBLIC;
