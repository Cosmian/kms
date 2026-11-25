-- Object lifecycle state as an insert-only replicated event log (PostgreSQL).
-- Executed as one multi-statement batch (not a rawsql entry: rawsql ends a query at the first line ending in `;`).

DROP TRIGGER IF EXISTS trg_objects_state_monotonic ON objects;
DROP FUNCTION IF EXISTS objects_state_monotonic_guard();

CREATE OR REPLACE FUNCTION kms_state_join(a text, b text) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $f$
DECLARE
  phase int;
  compromised boolean;
BEGIN
  IF a IS NULL THEN RETURN b; END IF;
  IF b IS NULL THEN RETURN a; END IF;
  phase := GREATEST(
    CASE a WHEN 'PreActive' THEN 1 WHEN 'Active' THEN 2 WHEN 'Deactivated' THEN 3
      WHEN 'Compromised' THEN 3 WHEN 'Destroyed' THEN 4 WHEN 'Destroyed_Compromised' THEN 4
      ELSE 0 END,
    CASE b WHEN 'PreActive' THEN 1 WHEN 'Active' THEN 2 WHEN 'Deactivated' THEN 3
      WHEN 'Compromised' THEN 3 WHEN 'Destroyed' THEN 4 WHEN 'Destroyed_Compromised' THEN 4
      ELSE 0 END);
  compromised := a IN ('Compromised', 'Destroyed_Compromised')
              OR b IN ('Compromised', 'Destroyed_Compromised');
  RETURN CASE
    WHEN phase = 4 AND compromised THEN 'Destroyed_Compromised'
    WHEN phase = 4 THEN 'Destroyed'
    WHEN compromised THEN 'Compromised'
    WHEN phase = 3 THEN 'Deactivated'
    WHEN phase = 2 THEN 'Active'
    WHEN phase = 1 THEN 'PreActive'
    ELSE a END;
END;
$f$;

CREATE OR REPLACE FUNCTION kms_effective_state(p_object_id varchar) RETURNS text
LANGUAGE plpgsql STABLE AS $f$
DECLARE
  acc text;
  ev text;
BEGIN
  FOR ev IN
    SELECT e.state FROM object_state_events e
    WHERE e.object_id = p_object_id
      AND NOT EXISTS (SELECT 1 FROM object_state_event_tombstones t WHERE t.event_id = e.event_id)
  LOOP
    acc := kms_state_join(acc, ev);
  END LOOP;
  RETURN acc;
END;
$f$;

CREATE OR REPLACE FUNCTION objects_state_derive() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  eff text;
  destroyed record;
BEGIN
  eff := kms_effective_state(NEW.id);
  IF eff IS NULL THEN
    RETURN NEW;
  END IF;
  NEW.state := eff;
  IF eff IN ('Destroyed', 'Destroyed_Compromised') THEN
    SELECT e.object, e.wrapping_key_id INTO destroyed
    FROM object_state_events e
    WHERE e.object_id = NEW.id AND e.object IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM object_state_event_tombstones t WHERE t.event_id = e.event_id)
    ORDER BY e.recorded_at, e.event_id
    LIMIT 1;
    IF FOUND THEN
      NEW.object := destroyed.object;
      NEW.wrapping_key_id := destroyed.wrapping_key_id;
    END IF;
  END IF;
  RETURN NEW;
END;
$f$;

DROP TRIGGER IF EXISTS trg_objects_state_derive ON objects;
CREATE TRIGGER trg_objects_state_derive
  BEFORE INSERT OR UPDATE ON objects
  FOR EACH ROW EXECUTE FUNCTION objects_state_derive();
ALTER TABLE objects ENABLE ALWAYS TRIGGER trg_objects_state_derive;

CREATE OR REPLACE FUNCTION object_state_events_apply() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  UPDATE objects SET state = state, version = version + 1 WHERE id = NEW.object_id;
  RETURN NULL;
END;
$f$;

DROP TRIGGER IF EXISTS trg_object_state_events_apply ON object_state_events;
CREATE TRIGGER trg_object_state_events_apply
  AFTER INSERT ON object_state_events
  FOR EACH ROW EXECUTE FUNCTION object_state_events_apply();
ALTER TABLE object_state_events ENABLE ALWAYS TRIGGER trg_object_state_events_apply;

CREATE OR REPLACE FUNCTION object_state_event_tombstones_apply() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  UPDATE objects SET state = state, version = version + 1
  WHERE id = (SELECT object_id FROM object_state_events WHERE event_id = NEW.event_id);
  RETURN NULL;
END;
$f$;

DROP TRIGGER IF EXISTS trg_object_state_event_tombstones_apply ON object_state_event_tombstones;
CREATE TRIGGER trg_object_state_event_tombstones_apply
  AFTER INSERT ON object_state_event_tombstones
  FOR EACH ROW EXECUTE FUNCTION object_state_event_tombstones_apply();
ALTER TABLE object_state_event_tombstones
  ENABLE ALWAYS TRIGGER trg_object_state_event_tombstones_apply;
