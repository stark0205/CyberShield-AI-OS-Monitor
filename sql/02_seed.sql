-- CyberShield AI - sample data
-- password for admin is: admin123
-- pwd_hash is set by backend/setup_db.py (bcrypt)

USE cybershield;

-- admin user is inserted by setup_db.py so hash is real

INSERT INTO device (uid, dname, os_type, ip_addr)
VALUES (1, 'dev-laptop', 'macOS', '127.0.0.1');

INSERT INTO sec_event (did, etype, details, pid, cpu_pct, mem_mb, exe_name)
VALUES
    (1, 'high_cpu', 'Process using high CPU', 4521, 95.2, 312.5, 'crypto_miner'),
    (1, 'file_mod', 'File changed', 1200, 2.1, 45.0, 'TextEdit'),
    (1, 'new_proc', 'Unknown process started', 7788, 15.0, 128.3, 'strange_app'),
    (1, 'mem_spike', 'Memory usage high', 3300, 40.5, 2048.0, 'Chrome'),
    (1, 'normal', 'Normal activity', 1100, 1.0, 20.0, 'Finder');
