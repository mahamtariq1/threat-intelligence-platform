<?php
require_once '../includes/session_check.php';
require_role(['expert','org_admin']);
require_once '../includes/db.php';
$case_id = intval($_GET['id'] ?? 0);
$uid = $_SESSION['user_id'];
$role = $_SESSION['role'];
$oid = $_SESSION['org_id'];

if ($role === 'expert') {
    $stmt = $conn->prepare("SELECT c.*, u.full_name as reporter, m.name as mitre_name, m.tactic as mitre_tactic, m.technique_id as mitre_tid, m.description as mitre_desc FROM cases c JOIN users u ON c.reported_by = u.id LEFT JOIN mitre_techniques m ON c.mitre_technique_id = m.id WHERE c.id = ? AND c.assigned_to = ?");
    $stmt->bind_param("ii", $case_id, $uid);
} else {
    $stmt = $conn->prepare("SELECT c.*, u.full_name as reporter, m.name as mitre_name, m.tactic as mitre_tactic, m.technique_id as mitre_tid, m.description as mitre_desc FROM cases c JOIN users u ON c.reported_by = u.id LEFT JOIN mitre_techniques m ON c.mitre_technique_id = m.id WHERE c.id = ? AND c.org_id = ?");
    $stmt->bind_param("ii", $case_id, $oid);
}
$stmt->execute(); $case = $stmt->get_result()->fetch_assoc();
if (!$case) { echo "Access denied."; exit(); }

$iocs_q = $conn->prepare("SELECT DISTINCT i.ioc_value, i.ioc_type, i.times_seen FROM ioc_sightings s JOIN iocs i ON s.ioc_id = i.id WHERE s.case_id = ?");
$iocs_q->bind_param("i",$case_id); $iocs_q->execute(); $iocs = $iocs_q->get_result()->fetch_all(MYSQLI_ASSOC);

$rules_q = $conn->prepare("SELECT r.name, l.score_added, l.matched_value FROM rule_match_logs l JOIN severity_rules r ON l.rule_id = r.id WHERE l.case_id = ? ORDER BY l.score_added DESC");
$rules_q->bind_param("i",$case_id); $rules_q->execute(); $rules = $rules_q->get_result()->fetch_all(MYSQLI_ASSOC);

$logs_q = $conn->prepare("SELECT l.action, l.details, l.created_at, u.full_name FROM case_logs l LEFT JOIN users u ON l.user_id = u.id WHERE l.case_id = ? ORDER BY l.created_at ASC");
$logs_q->bind_param("i",$case_id); $logs_q->execute(); $logs = $logs_q->get_result()->fetch_all(MYSQLI_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Incident Report — Case #<?= $case_id ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
    body { font-family: Arial, sans-serif; font-size: 13px; background: white; }
    .report-header { background: #1F4E79; color: white; padding: 20px 30px; margin-bottom: 20px; }
    .section-title { color: #1F4E79; border-bottom: 2px solid #1F4E79; padding-bottom: 4px; margin: 20px 0 10px; font-weight: bold; font-size: 14px; }
    .severity-Critical { background:#dc3545; color:white; padding:2px 10px; border-radius:10px; }
    .severity-High { background:#fd7e14; color:white; padding:2px 10px; border-radius:10px; }
    .severity-Medium { background:#ffc107; color:black; padding:2px 10px; border-radius:10px; }
    .severity-Low { background:#198754; color:white; padding:2px 10px; border-radius:10px; }
    .ioc-tag { display:inline-block; background:#e8f0fe; color:#1a56db; border-radius:10px; padding:1px 8px; margin:2px; font-family:monospace; font-size:11px; }
    .rule-row { background:#fff8e7; border-left:3px solid #fd7e14; padding:4px 8px; margin-bottom:4px; border-radius:0 4px 4px 0; }
    .log-item { border-left:3px solid #0d6efd; padding:4px 8px; margin-bottom:4px; background:#f8f9fa; border-radius:0 4px 4px 0; }
    table th { background:#1F4E79; color:white; }
    @media print { .no-print { display:none; } }
</style>
</head>
<body>
<div class="report-header">
    <div class="d-flex justify-content-between align-items-center">
        <div>
            <h4 class="mb-0">🛡 Incident Report</h4>
            <small>ThreatIntel Platform — Cyber Incident Response System</small>
        </div>
        <div class="text-end">
            <strong>Case #<?= $case_id ?></strong><br>
            <small>Generated: <?= date('d M Y H:i') ?></small>
        </div>
    </div>
</div>
<div class="container-fluid px-4">
    <button class="btn btn-primary btn-sm mb-3 no-print" onclick="window.print()"><i>🖨</i> Print / Save as PDF</button>

    <div class="section-title">1. Case Overview</div>
    <table class="table table-bordered table-sm">
        <tr><th width="20%">Case ID</th><td>#<?= $case_id ?></td><th width="20%">Filed By</th><td><?= htmlspecialchars($case['reporter']) ?></td></tr>
        <tr><th>Title</th><td><?= htmlspecialchars($case['title']) ?></td><th>Date Filed</th><td><?= date('d M Y H:i', strtotime($case['created_at'])) ?></td></tr>
        <tr><th>Attack Type</th><td><?= htmlspecialchars($case['attack_type']) ?></td><th>Status</th><td><?= ucfirst(str_replace('_',' ',$case['status'])) ?></td></tr>
        <tr><th>Severity</th><td><span class="severity-<?= $case['severity'] ?>"><?= $case['severity'] ?></span></td><th>Severity Score</th><td><strong><?= $case['severity_score'] ?></strong></td></tr>
    </table>

    <div class="section-title">2. Incident Description</div>
    <p><?= nl2br(htmlspecialchars($case['description'])) ?></p>

    <div class="section-title">3. MITRE ATT&CK Mapping</div>
    <?php if ($case['mitre_name']): ?>
    <table class="table table-bordered table-sm">
        <tr><th>Technique ID</th><td><?= htmlspecialchars($case['mitre_tid']) ?></td><th>Name</th><td><?= htmlspecialchars($case['mitre_name']) ?></td></tr>
        <tr><th>Tactic</th><td><?= htmlspecialchars($case['mitre_tactic']) ?></td><th>Description</th><td><?= htmlspecialchars($case['mitre_desc']) ?></td></tr>
    </table>
    <?php else: ?><p class="text-muted">No MITRE technique identified for this case.</p><?php endif; ?>

    <div class="section-title">4. Extracted Indicators of Compromise (<?= count($iocs) ?>)</div>
    <?php if ($iocs): ?>
    <?php foreach($iocs as $ioc): ?>
    <span class="ioc-tag"><strong><?= $ioc['ioc_type'] ?>:</strong> <?= htmlspecialchars($ioc['ioc_value']) ?> (seen <?= $ioc['times_seen'] ?>x)</span>
    <?php endforeach; ?>
    <?php else: ?><p class="text-muted">No IOCs extracted from this case.</p><?php endif; ?>

    <div class="section-title">5. Rule-Based Analysis — Score Breakdown (Total: <?= $case['severity_score'] ?>)</div>
    <?php if ($rules): ?>
    <?php foreach($rules as $r): ?>
    <div class="rule-row"><strong><?= htmlspecialchars($r['name']) ?></strong> &mdash; Matched: <code><?= htmlspecialchars($r['matched_value']) ?></code> <span class="float-end"><strong>+<?= $r['score_added'] ?> pts</strong></span></div>
    <?php endforeach; ?>
    <?php else: ?><p class="text-muted">No rules matched for this case.</p><?php endif; ?>

    <div class="section-title">6. Case Audit Trail</div>
    <?php foreach($logs as $log): ?>
    <div class="log-item">
        <strong><?= htmlspecialchars(ucwords(str_replace('_',' ',$log['action']))) ?></strong>
        <?php if($log['full_name']): ?> — <?= htmlspecialchars($log['full_name']) ?><?php endif; ?>
        <span class="float-end text-muted"><?= date('d M Y H:i', strtotime($log['created_at'])) ?></span>
        <?php if($log['details']): ?><br><span class="text-muted"><?= htmlspecialchars($log['details']) ?></span><?php endif; ?>
    </div>
    <?php endforeach; ?>

    <div class="mt-4 text-center text-muted" style="font-size:11px;border-top:1px solid #ddd;padding-top:10px;">
        ThreatIntel Platform &mdash; Collaborative Cyber Incident Response System &mdash; <?= date('Y') ?>
    </div>
</div>
</body>
</html>
