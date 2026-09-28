-- Provision the restricted executor login, exactly as the foot of postgres.sql
-- prescribes. Run once by the database owner, after postgres.sql, with psql:
--
--   psql -h localhost -U <owner> -d <claim database> \
--     -v executor_password=<password> -v namespace=<MNDE_GIT_PUSH_NAMESPACE> \
--     -f deployment/freshness/provision-executor-login.sql
--
-- psql substitutes the two variables; nothing else is configurable here. The
-- login gets USAGE on the schema, EXECUTE on the three claim functions and
-- CONNECT on this database, and nothing else: no table writes, no ownership, no
-- role switching. Its namespace binding cannot be changed by the login itself.
\set ON_ERROR_STOP on
CREATE ROLE mnde_executor LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'executor_password';
INSERT INTO mnde_claim.executor_namespaces VALUES ('mnde_executor', :'namespace');
GRANT USAGE ON SCHEMA mnde_claim TO mnde_executor;
GRANT EXECUTE ON FUNCTION mnde_claim.bound_namespace(), mnde_claim.first_claim(jsonb), mnde_claim.lookup_claim(jsonb) TO mnde_executor;
SELECT current_database() AS claim_database \gset
REVOKE ALL ON DATABASE :"claim_database" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"claim_database" TO mnde_executor;
