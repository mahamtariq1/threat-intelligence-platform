<?php
// ============================================================
// ThreatEngine — Rule-Based Incident Analysis Engine
// Extracts IOCs, scores severity, maps MITRE ATT&CK
// Auto-triggered on every case submission
// ============================================================

class ThreatEngine {

    private $conn;
    private $case_id;
    private $org_id;
    private $description;
    private $extracted_iocs = [];
    private $total_score = 0;
    private $severity = 'Low';
    private $matched_mitre_id = null;

    public function __construct($conn) {
        $this->conn = $conn;
    }

    // Main entry point — call this after inserting a case
    public function analyze($case_id, $org_id, $description) {
        $this->case_id    = $case_id;
        $this->org_id     = $org_id;
        $this->description = $description;

        $this->extractIOCs();
        $this->evaluateRules();
        $this->assignSeverity();
        $this->updateCase();
        $this->generateCrossOrgAlerts();
    }

    // ── 1. IOC EXTRACTION ─────────────────────────────────────

    private function extractIOCs() {
        $text = $this->description;
        $found = [];

        // IPv4
        preg_match_all('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $text, $m);
        foreach ($m[0] as $v) $found[] = ['value' => $v, 'type' => 'ip'];

        // Domain names (not IPs)
        preg_match_all('/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|io|co|uk|pk|info|biz|xyz)\b/i', $text, $m);
        foreach ($m[0] as $v) {
            if (!preg_match('/^\d+\.\d+\.\d+\.\d+$/', $v)) $found[] = ['value' => $v, 'type' => 'domain'];
        }

        // URLs
        preg_match_all('/https?:\/\/[^\s\'"<>]+/i', $text, $m);
        foreach ($m[0] as $v) $found[] = ['value' => $v, 'type' => 'url'];

        // Email addresses
        preg_match_all('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/i', $text, $m);
        foreach ($m[0] as $v) $found[] = ['value' => $v, 'type' => 'email'];

        // MD5 hashes (32 hex chars)
        preg_match_all('/\b[a-fA-F0-9]{32}\b/', $text, $m);
        foreach ($m[0] as $v) $found[] = ['value' => $v, 'type' => 'md5'];

        // SHA256 hashes (64 hex chars)
        preg_match_all('/\b[a-fA-F0-9]{64}\b/', $text, $m);
        foreach ($m[0] as $v) $found[] = ['value' => $v, 'type' => 'sha256'];

        // Deduplicate by value
        $seen = [];
        foreach ($found as $ioc) {
            if (!in_array($ioc['value'], $seen)) {
                $seen[] = $ioc['value'];
                $this->storeIOC($ioc['value'], $ioc['type']);
            }
        }
    }

    private function storeIOC($value, $type) {
        // Check if IOC already exists globally
        $stmt = $this->conn->prepare("SELECT id, times_seen FROM iocs WHERE ioc_value = ?");
        $stmt->bind_param("s", $value);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($row = $result->fetch_assoc()) {
            // Update existing
            $ioc_id = $row['id'];
            $upd = $this->conn->prepare("UPDATE iocs SET times_seen = times_seen + 1, last_seen = NOW() WHERE id = ?");
            $upd->bind_param("i", $ioc_id);
            $upd->execute();
        } else {
            // Insert new
            $ins = $this->conn->prepare("INSERT INTO iocs (ioc_value, ioc_type) VALUES (?, ?)");
            $ins->bind_param("ss", $value, $type);
            $ins->execute();
            $ioc_id = $this->conn->insert_id;
        }

        // Create sighting record
        $sight = $this->conn->prepare("INSERT INTO ioc_sightings (ioc_id, case_id, org_id) VALUES (?, ?, ?)");
        $sight->bind_param("iii", $ioc_id, $this->case_id, $this->org_id);
        $sight->execute();

        $this->extracted_iocs[] = ['id' => $ioc_id, 'value' => $value, 'type' => $type];
    }

    // ── 2. RULE EVALUATION ────────────────────────────────────

    private function evaluateRules() {
        $text = strtolower($this->description);
        $stmt = $this->conn->prepare("SELECT id, name, condition_keyword, score_add, mitre_technique_id FROM severity_rules WHERE is_active = 1");
        $stmt->execute();
        $rules = $stmt->get_result();

        $top_score = 0;

        while ($rule = $rules->fetch_assoc()) {
            $keyword = strtolower($rule['condition_keyword']);
            if (strpos($text, $keyword) !== false) {
                $this->total_score += $rule['score_add'];

                // Log this rule match
                $matched_val = $rule['condition_keyword'];
                $log = $this->conn->prepare("INSERT INTO rule_match_logs (case_id, rule_id, score_added, matched_value) VALUES (?, ?, ?, ?)");
                $log->bind_param("iiis", $this->case_id, $rule['id'], $rule['score_add'], $matched_val);
                $log->execute();

                // Track highest-scoring rule with a MITRE technique
                if ($rule['mitre_technique_id'] && $rule['score_add'] > $top_score) {
                    $top_score = $rule['score_add'];
                    $this->matched_mitre_id = $rule['mitre_technique_id'];
                }
            }
        }
    }

    // ── 3. SEVERITY ASSIGNMENT ────────────────────────────────

    private function assignSeverity() {
        if ($this->total_score >= 71)      $this->severity = 'Critical';
        elseif ($this->total_score >= 46)  $this->severity = 'High';
        elseif ($this->total_score >= 21)  $this->severity = 'Medium';
        else                               $this->severity = 'Low';
    }

    // ── 4. UPDATE CASE ────────────────────────────────────────

    private function updateCase() {
        $stmt = $this->conn->prepare("UPDATE cases SET severity_score = ?, severity = ?, mitre_technique_id = ? WHERE id = ?");
        $stmt->bind_param("isii", $this->total_score, $this->severity, $this->matched_mitre_id, $this->case_id);
        $stmt->execute();
    }

    // ── 5. CROSS-ORG ALERTS ───────────────────────────────────

    private function generateCrossOrgAlerts() {
        foreach ($this->extracted_iocs as $ioc) {
            // Find other orgs that have seen this IOC before
            $stmt = $this->conn->prepare("
                SELECT DISTINCT org_id FROM ioc_sightings
                WHERE ioc_id = ? AND org_id != ? AND case_id != ?
            ");
            $stmt->bind_param("iii", $ioc['id'], $this->org_id, $this->case_id);
            $stmt->execute();
            $orgs = $stmt->get_result();

            while ($org = $orgs->fetch_assoc()) {
                $msg = "IOC '{$ioc['value']}' ({$ioc['type']}) detected in a new case from another organization. This indicator was previously seen in your cases.";
                $alert = $this->conn->prepare("INSERT INTO alerts (org_id, case_id, ioc_id, message) VALUES (?, ?, ?, ?)");
                $alert->bind_param("iiis", $org['org_id'], $this->case_id, $ioc['id'], $msg);
                $alert->execute();
            }
        }
    }

    // ── GETTERS ───────────────────────────────────────────────

    public function getSeverity()   { return $this->severity; }
    public function getScore()      { return $this->total_score; }
    public function getIOCs()       { return $this->extracted_iocs; }
    public function getMitreId()    { return $this->matched_mitre_id; }
}
?>
