-- ============================================================
-- Threat Intelligence & Incident Response Platform
-- Database: threat_intel_db
-- ============================================================

CREATE DATABASE IF NOT EXISTS threat_intel_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE threat_intel_db;

-- 1. Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    type VARCHAR(100) NOT NULL,
    country VARCHAR(100) NOT NULL,
    is_active TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. Users
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_id INT DEFAULT NULL,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('platform_admin','org_admin','expert','employee') NOT NULL,
    is_active TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 3. MITRE ATT&CK Techniques
CREATE TABLE IF NOT EXISTS mitre_techniques (
    id INT AUTO_INCREMENT PRIMARY KEY,
    technique_id VARCHAR(20) NOT NULL,
    name VARCHAR(200) NOT NULL,
    tactic VARCHAR(100) NOT NULL,
    description TEXT
) ENGINE=InnoDB;

-- 4. Severity Rules
CREATE TABLE IF NOT EXISTS severity_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    condition_keyword VARCHAR(200) NOT NULL,
    score_add INT NOT NULL DEFAULT 10,
    mitre_technique_id INT DEFAULT NULL,
    is_active TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mitre_technique_id) REFERENCES mitre_techniques(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 5. Cases
CREATE TABLE IF NOT EXISTS cases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    severity_score INT DEFAULT 0,
    severity ENUM('Low','Medium','High','Critical') DEFAULT 'Low',
    status ENUM('open','in_progress','resolved','closed') DEFAULT 'open',
    reported_by INT NOT NULL,
    assigned_to INT DEFAULT NULL,
    mitre_technique_id INT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (reported_by) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (mitre_technique_id) REFERENCES mitre_techniques(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 6. Case Logs (audit trail - append only)
CREATE TABLE IF NOT EXISTS case_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    user_id INT DEFAULT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 7. Case Attachments
CREATE TABLE IF NOT EXISTS case_attachments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    uploaded_by INT DEFAULT NULL,
    original_name VARCHAR(255) NOT NULL,
    stored_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 8. IOCs (global)
CREATE TABLE IF NOT EXISTS iocs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ioc_value VARCHAR(500) NOT NULL UNIQUE,
    ioc_type ENUM('ip','domain','url','email','md5','sha256') NOT NULL,
    reputation_score INT DEFAULT 0,
    times_seen INT DEFAULT 1,
    is_confirmed TINYINT(1) DEFAULT 0,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 9. IOC Sightings
CREATE TABLE IF NOT EXISTS ioc_sightings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ioc_id INT NOT NULL,
    case_id INT NOT NULL,
    org_id INT NOT NULL,
    seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 10. Rule Match Logs
CREATE TABLE IF NOT EXISTS rule_match_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    rule_id INT NOT NULL,
    score_added INT NOT NULL,
    matched_value VARCHAR(500),
    matched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (rule_id) REFERENCES severity_rules(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 11. Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_id INT NOT NULL,
    case_id INT NOT NULL,
    ioc_id INT NOT NULL,
    message TEXT NOT NULL,
    is_read TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Indexes
CREATE INDEX idx_cases_org ON cases(org_id);
CREATE INDEX idx_cases_status ON cases(status);
CREATE INDEX idx_ioc_sightings_ioc ON ioc_sightings(ioc_id);
CREATE INDEX idx_ioc_sightings_org ON ioc_sightings(org_id);
CREATE INDEX idx_alerts_org ON alerts(org_id);
CREATE INDEX idx_alerts_read ON alerts(is_read);

-- ============================================================
-- SEED: MITRE ATT&CK Techniques (15)
-- ============================================================
INSERT INTO mitre_techniques (technique_id, name, tactic, description) VALUES
('T1566','Phishing','Initial Access','Adversaries send phishing messages to gain access to victim systems.'),
('T1059','Command and Scripting Interpreter','Execution','Adversaries abuse command and script interpreters to execute commands.'),
('T1078','Valid Accounts','Defense Evasion','Adversaries use valid credentials to maintain access.'),
('T1486','Data Encrypted for Impact','Impact','Adversaries encrypt data on target systems to interrupt availability.'),
('T1071','Application Layer Protocol','Command and Control','Adversaries communicate using application layer protocols.'),
('T1190','Exploit Public-Facing Application','Initial Access','Adversaries exploit vulnerabilities in public-facing applications.'),
('T1133','External Remote Services','Persistence','Adversaries leverage external remote services for initial access.'),
('T1110','Brute Force','Credential Access','Adversaries use brute force techniques to gain access to accounts.'),
('T1055','Process Injection','Defense Evasion','Adversaries inject code into processes to evade detection.'),
('T1082','System Information Discovery','Discovery','Adversaries gather system information to shape follow-on behaviors.'),
('T1083','File and Directory Discovery','Discovery','Adversaries enumerate files and directories on a system.'),
('T1021','Remote Services','Lateral Movement','Adversaries use remote services to move laterally through environments.'),
('T1041','Exfiltration Over C2 Channel','Exfiltration','Adversaries steal data by exfiltrating it over the C2 channel.'),
('T1005','Data from Local System','Collection','Adversaries search local system sources to find files of interest.'),
('T1027','Obfuscated Files or Information','Defense Evasion','Adversaries attempt to make payloads difficult to discover or analyze.');

-- ============================================================
-- SEED: Severity Rules (20)
-- ============================================================
INSERT INTO severity_rules (name, condition_keyword, score_add, mitre_technique_id) VALUES
('Ransomware Detected', 'ransomware', 40, 4),
('Phishing Email', 'phishing', 25, 1),
('Brute Force Attempt', 'brute force', 20, 8),
('Malware Detected', 'malware', 35, 2),
('Data Exfiltration', 'exfiltration', 45, 13),
('Suspicious IP', 'suspicious ip', 15, 5),
('Unauthorized Access', 'unauthorized access', 30, 3),
('SQL Injection', 'sql injection', 35, 6),
('Credential Stuffing', 'credential stuffing', 25, 8),
('Command and Control', 'command and control', 40, 5),
('Lateral Movement', 'lateral movement', 35, 12),
('Process Injection', 'process injection', 30, 9),
('Remote Code Execution', 'remote code execution', 45, 6),
('Password Spray', 'password spray', 20, 8),
('Data Breach', 'data breach', 40, 14),
('Trojan Detected', 'trojan', 30, 2),
('DDoS Attack', 'ddos', 25, 5),
('Cryptominer', 'cryptominer', 20, 4),
('Keylogger', 'keylogger', 35, 14),
('Zero Day Exploit', 'zero day', 50, 6);

-- ============================================================
-- SEED: Platform Admin Account
-- Password: Admin@123
-- ============================================================
INSERT INTO users (org_id, full_name, email, password_hash, role) VALUES
(NULL, 'Platform Administrator', 'admin@platform.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'platform_admin');
