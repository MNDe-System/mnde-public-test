-- Run once by the independent database owner, never by the executor login.
-- Provision a restricted LOGIN separately. Bind it to exactly one immutable namespace.
CREATE SCHEMA mnde_claim;
REVOKE ALL ON SCHEMA mnde_claim FROM PUBLIC;
CREATE TABLE mnde_claim.executor_namespaces (
  login name PRIMARY KEY, namespace text NOT NULL CHECK (length(namespace) > 0)
);
CREATE TABLE mnde_claim.claims (
  namespace text NOT NULL CHECK (length(namespace) > 0),
  execution_id text NOT NULL CHECK (length(execution_id) > 0),
  grant_id text NOT NULL CHECK (length(grant_id) > 0),
  record jsonb NOT NULL,
  claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace, execution_id),
  UNIQUE(namespace, grant_id)
);
-- No expiry, deletion, unclaim, or reusable-authority operation exists.
CREATE FUNCTION mnde_claim.bound_namespace() RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mnde_claim AS $$
DECLARE ns text;
BEGIN
  SELECT namespace INTO STRICT ns FROM mnde_claim.executor_namespaces WHERE login = session_user;
  RETURN ns;
END $$;
CREATE FUNCTION mnde_claim.check_record(r jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mnde_claim AS $$
DECLARE ns text := mnde_claim.bound_namespace(); k text;
BEGIN
  IF jsonb_typeof(r) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'invalid claim'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(r)) <> 7 THEN RAISE EXCEPTION 'invalid fields'; END IF;
  FOREACH k IN ARRAY ARRAY['namespace','execution_id','grant_id','subject','executor_id','receipt_hash','aplus_digest'] LOOP
    IF jsonb_typeof(r->k) IS DISTINCT FROM 'string' OR length(r->>k) = 0 THEN RAISE EXCEPTION 'invalid identity'; END IF;
  END LOOP;
  IF r->>'namespace' <> ns THEN RAISE EXCEPTION 'wrong namespace'; END IF;
  RETURN ns;
END $$;
CREATE FUNCTION mnde_claim.first_claim(r jsonb) RETURNS TABLE(inserted boolean, record jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mnde_claim AS $$
DECLARE ns text := mnde_claim.check_record(r); saved jsonb;
BEGIN
  INSERT INTO mnde_claim.claims(namespace,execution_id,grant_id,record)
    VALUES(ns,r->>'execution_id',r->>'grant_id',r)
    ON CONFLICT DO NOTHING RETURNING claims.record INTO saved;
  IF saved IS NOT NULL THEN RETURN QUERY SELECT true, saved;
  ELSE
    -- At READ COMMITTED this statement observes the winning transaction after
    -- the unique-index conflict wait; either identity independently spends authority.
    RETURN QUERY SELECT false, c.record FROM mnde_claim.claims c
      WHERE c.namespace=ns AND (c.execution_id=r->>'execution_id' OR c.grant_id=r->>'grant_id') LIMIT 1;
  END IF;
END $$;
CREATE FUNCTION mnde_claim.lookup_claim(r jsonb) RETURNS TABLE(record jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mnde_claim AS $$
DECLARE ns text := mnde_claim.check_record(r);
BEGIN
  RETURN QUERY SELECT c.record FROM mnde_claim.claims c
    WHERE c.namespace=ns AND (c.execution_id=r->>'execution_id' OR c.grant_id=r->>'grant_id');
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA mnde_claim FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mnde_claim FROM PUBLIC;
-- Operator applies to a dedicated, non-owner, non-superuser, NOINHERIT login:
-- INSERT INTO mnde_claim.executor_namespaces VALUES ('executor_login', 'immutable-namespace');
-- GRANT USAGE ON SCHEMA mnde_claim TO executor_login;
-- GRANT EXECUTE ON FUNCTION mnde_claim.bound_namespace(),
--   mnde_claim.first_claim(jsonb), mnde_claim.lookup_claim(jsonb) TO executor_login;
-- Do NOT grant table writes, schema ownership, role switching, or snapshot privileges.
