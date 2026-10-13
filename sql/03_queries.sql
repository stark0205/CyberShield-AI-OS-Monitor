-- useful queries for DBMS demo
USE cybershield;

-- 1. JOIN: events with AI risk
SELECT e.eid, e.etype, e.exe_name, e.ts, t.risk_lvl, t.confidence
FROM sec_event e
LEFT JOIN threat t ON e.eid = t.eid
ORDER BY e.ts DESC;

-- 2. count by risk
SELECT risk_lvl, COUNT(*) AS cnt
FROM threat
GROUP BY risk_lvl
ORDER BY cnt DESC;

-- 3. high risk not investigated yet
SELECT e.eid, e.etype, e.exe_name
FROM sec_event e
WHERE e.eid IN (
    SELECT t.eid FROM threat t
    WHERE t.risk_lvl = 'High Risk'
    AND t.tid NOT IN (SELECT i.tid FROM investigation i)
);

-- 4. transaction example
-- The AFTER INSERT trigger adds the matching audit row in this transaction.
START TRANSACTION;
    INSERT INTO investigation (tid, uid, status, notes)
    VALUES (1, 1, 'Open', 'Checking high CPU process');
COMMIT;

-- 5. full trail: event -> threat -> inv -> response
SELECT e.eid, e.etype, t.risk_lvl, i.status, r.action_type, r.done_at
FROM sec_event e
JOIN threat t ON e.eid = t.eid
JOIN investigation i ON t.tid = i.tid
JOIN resp_action r ON i.inv_id = r.inv_id
ORDER BY e.ts DESC;

-- 6. daily summary
SELECT DATE(ts) AS day, etype, COUNT(*) AS total
FROM sec_event
GROUP BY DATE(ts), etype
ORDER BY day DESC, total DESC;
