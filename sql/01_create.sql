-- CyberShield AI - create database and tables
-- MySQL 8.0+

CREATE DATABASE IF NOT EXISTS cybershield;
USE cybershield;

CREATE TABLE IF NOT EXISTS usr (
    uid         INT AUTO_INCREMENT PRIMARY KEY,
    uname       VARCHAR(50) NOT NULL UNIQUE,
    email       VARCHAR(100) NOT NULL UNIQUE,
    pwd_hash    VARCHAR(255) NOT NULL,
    role        VARCHAR(20) DEFAULT 'admin',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device (
    did         INT AUTO_INCREMENT PRIMARY KEY,
    uid         INT NOT NULL,
    dname       VARCHAR(100) NOT NULL,
    os_type     VARCHAR(30) NOT NULL,
    ip_addr     VARCHAR(45),
    reg_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uid) REFERENCES usr(uid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sec_event (
    eid         INT AUTO_INCREMENT PRIMARY KEY,
    did         INT NOT NULL,
    etype       VARCHAR(50) NOT NULL,
    details     TEXT,
    pid         INT,
    ppid        INT,
    proc_state  VARCHAR(32),
    cpu_pct     FLOAT CHECK (cpu_pct >= 0),
    mem_mb      FLOAT CHECK (mem_mb >= 0),
    exe_name    VARCHAR(255),
    ts          DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (did) REFERENCES device(did) ON DELETE CASCADE
);

-- stores AI label for each event (Normal / Suspicious / High Risk)
CREATE TABLE IF NOT EXISTS threat (
    tid         INT AUTO_INCREMENT PRIMARY KEY,
    eid         INT NOT NULL UNIQUE,
    confidence  FLOAT CHECK (confidence >= 0 AND confidence <= 1),
    risk_lvl    VARCHAR(20) NOT NULL
        CHECK (risk_lvl IN ('Normal', 'Suspicious', 'High Risk')),
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (eid) REFERENCES sec_event(eid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS investigation (
    inv_id      INT AUTO_INCREMENT PRIMARY KEY,
    tid         INT NOT NULL,
    uid         INT NOT NULL,
    status      VARCHAR(30) DEFAULT 'Open'
        CHECK (status IN ('Open', 'In Progress', 'Closed')),
    notes       TEXT,
    started_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    closed_at   DATETIME,
    FOREIGN KEY (tid) REFERENCES threat(tid) ON DELETE CASCADE,
    FOREIGN KEY (uid) REFERENCES usr(uid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS resp_action (
    raid        INT AUTO_INCREMENT PRIMARY KEY,
    inv_id      INT NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    description TEXT,
    done_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inv_id) REFERENCES investigation(inv_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    log_id      INT AUTO_INCREMENT PRIMARY KEY,
    uid         INT,
    action      VARCHAR(100) NOT NULL,
    detail      TEXT,
    ts          DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uid) REFERENCES usr(uid) ON DELETE SET NULL
);

CREATE INDEX idx_event_ts ON sec_event(ts);
CREATE INDEX idx_event_did ON sec_event(did);
CREATE INDEX idx_threat_risk ON threat(risk_lvl);
CREATE INDEX idx_inv_status ON investigation(status);
CREATE INDEX idx_audit_ts ON audit_log(ts);
