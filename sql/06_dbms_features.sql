-- Live DBMS features used by the CyberShield API.
-- Safe to rerun; no application tables or existing records are dropped.
USE cybershield;

CREATE OR REPLACE VIEW v_investigation_summary AS
SELECT i.*, t.risk_lvl, e.exe_name
FROM investigation AS i
JOIN threat AS t ON i.tid = t.tid
JOIN sec_event AS e ON t.eid = e.eid;

DROP TRIGGER IF EXISTS trg_investigation_audit_insert;
DROP TRIGGER IF EXISTS trg_response_audit_insert;
DROP PROCEDURE IF EXISTS sp_open_investigation;
DROP PROCEDURE IF EXISTS sp_add_response;

DELIMITER $$

CREATE TRIGGER trg_investigation_audit_insert
AFTER INSERT ON investigation
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (uid, action, detail)
    VALUES (
        NEW.uid,
        'OPEN_INVESTIGATION',
        CONCAT('inv_id=', NEW.inv_id, ' tid=', NEW.tid)
    );
END$$

CREATE TRIGGER trg_response_audit_insert
AFTER INSERT ON resp_action
FOR EACH ROW
BEGIN
    DECLARE v_uid INT;

    SELECT uid INTO v_uid
    FROM investigation
    WHERE inv_id = NEW.inv_id;

    INSERT INTO audit_log (uid, action, detail)
    VALUES (
        COALESCE(@cs_actor_uid, v_uid),
        'ADD_RESPONSE',
        CONCAT('raid=', NEW.raid, ' type=', NEW.action_type)
    );
END$$

CREATE PROCEDURE sp_open_investigation(
    IN p_tid INT,
    IN p_uid INT,
    IN p_notes TEXT
)
BEGIN
    DECLARE v_inv_id INT;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;

    INSERT INTO investigation (tid, uid, status, notes)
    VALUES (p_tid, p_uid, 'Open', COALESCE(p_notes, ''));
    SET v_inv_id = LAST_INSERT_ID();

    COMMIT;
    SELECT v_inv_id AS inv_id;
END$$

CREATE PROCEDURE sp_add_response(
    IN p_inv_id INT,
    IN p_uid INT,
    IN p_action_type VARCHAR(50),
    IN p_description TEXT
)
BEGIN
    DECLARE v_raid INT;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        SET @cs_actor_uid = NULL;
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;

    IF NOT EXISTS (
        SELECT 1 FROM investigation WHERE inv_id = p_inv_id
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'investigation not found';
    END IF;

    SET @cs_actor_uid = p_uid;
    INSERT INTO resp_action (inv_id, action_type, description)
    VALUES (p_inv_id, p_action_type, COALESCE(p_description, ''));
    SET v_raid = LAST_INSERT_ID();
    SET @cs_actor_uid = NULL;

    COMMIT;
    SELECT v_raid AS raid;
END$$

DELIMITER ;
