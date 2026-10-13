-- Relational algebra demonstrations using the CyberShield schema.
-- These are read-only examples; run after sql/01_create.sql and seed data.
USE cybershield;

-- Selection (sigma): choose rows that satisfy a condition.
-- Relational algebra: sigma etype='high_cpu' (sec_event)
SELECT eid, did, etype, exe_name
FROM sec_event
WHERE etype = 'high_cpu';

-- Projection (pi): choose only the required columns.
-- Relational algebra: pi exe_name, cpu_pct (sec_event)
SELECT exe_name, cpu_pct
FROM sec_event;

-- Union: combine compatible results and remove duplicate rows.
-- Return event IDs whose type is either high_cpu or file_mod.
SELECT eid
FROM sec_event
WHERE etype = 'high_cpu'
UNION
SELECT eid
FROM sec_event
WHERE etype = 'file_mod';

-- Set difference: events that do not have a matching threat row.
-- SQL uses NOT EXISTS to express sec_event - (sec_event JOIN threat).
SELECT e.eid, e.etype, e.exe_name
FROM sec_event AS e
WHERE NOT EXISTS (
    SELECT 1
    FROM threat AS t
    WHERE t.eid = e.eid
);

-- Join: combine related tuples using the device foreign key.
-- Relational algebra: device JOIN sec_event ON device.did=sec_event.did
SELECT d.did, d.dname, e.eid, e.etype, e.exe_name, e.ts
FROM device AS d
JOIN sec_event AS e ON e.did = d.did;

-- Division: find devices that have produced every event type in the
-- required set (high_cpu and file_mod). The nested NOT EXISTS pattern
-- expresses "there is no required type missing for this device".
SELECT d.did, d.dname
FROM device AS d
WHERE NOT EXISTS (
    SELECT 1
    FROM (
        SELECT 'high_cpu' AS etype
        UNION
        SELECT 'file_mod'
    ) AS required_types
    WHERE NOT EXISTS (
        SELECT 1
        FROM sec_event AS e
        WHERE e.did = d.did
          AND e.etype = required_types.etype
    )
);
