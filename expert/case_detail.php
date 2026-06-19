<?php
require_once '../includes/session_check.php';
require_role(['expert']);
require_once '../includes/db.php';
$page_title = 'Case Investigation';
$uid = $_SESSION['user_id'];
$case_id = intval($_GET['id'] ?? 0);
$error = ''; $success = '';

// Verify this case is assigned to this expert
$stmt = $conn->prepare("SELECT c.*, u.full_name as reporter, m.name as mitre_name, m.tactic as mitre_tactic, m.technique_id as mitre_tid, m.description as mitre_desc FROM cases c JOIN users u ON c.reported_by = u.id LEFT JOIN mitre_techniques m ON c.mitre_technique_id = m.id WHERE c.id = ? AND c.assigned_to = ?");
$stmt->bind_param("ii", $case_id, $uid); $stmt->execute();
$case = $stmt->get_result()->fetch_assoc();
if (!$case) { header("Location: /threat_intel/expert/my_cases.php"); exit(); }

// Handle status update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'update_status') {
        $allowed = ['open','in_progress','resolved','closed'];
        $new_status = $_POST['status'] ?? '';
        if (in_array($new_status, $allowed)) {
            $upd = $conn->prepare("UPDATE cases SET status = ? WHERE id = ?");
            $upd->bind_param("si", $new_status, $case_id); $upd->execute();
            $log = $conn->prepare("INSERT INTO case_logs (case_id, user_id, action, details) VALUES (?, ?, 'status_updated', ?)");
            $detail = "Status changed to: $new_status";
            $log->bind_param("iis", $case_id, $uid, $detail); $log->execute();
            $case['status'] = $new_status;
            $success = "Status updated to: " . str_replace('_',' ', $new_status);
        }
    } elseif ($_POST['action'] === 'add_note') {
        $note = trim($_POST['note'] ?? '');
        if ($note) {
            $log = $conn->prepare("INSERT INTO case_logs (case_id, user_id, action, details) VALUES (?, ?, 'investigation_note', ?)");
            $log->bind_param("iis", $case_id, $uid, $note); $log->execute();
            $success = "Investigation note added.";
        } else {
            $error = "Note cannot be empty.";
        }
    }
}

// Fetch IOCs
$iocs_q = $conn->prepare("SELECT DISTINCT i.ioc_value, i.ioc_type, i.times_seen, i.is_confirmed FROM ioc_sightings s JOIN iocs i ON s.ioc_id = i.id WHERE s.case_id = ?");
$iocs_q->bind_param("i", $case_id); $iocs_q->execute(); $iocs = $iocs_q->get_result()->fetch_all(MYSQLI_ASSOC);

// Fetch rule matches
$rules_q = $conn->prepare("SELECT r.name, r.condition_keyword, l.score_added, l.matched_value FROM rule_match_logs l JOIN severity_rules r ON l.rule_id = r.id WHERE l.case_id = ? ORDER BY l.score_added DESC");
$rules_q->bind_param("i", $case_id); $rules_q->execute(); $rules = $rules_q->get_result()->fetch_all(MYSQLI_ASSOC);

// Fetch audit log
$logs_q = $conn->prepare("SELECT l.action, l.details, l.created_at, u.full_name FROM case_logs l LEFT JOIN users u ON l.user_id = u.id WHERE l.case_id = ? ORDER BY l.created_at ASC");
$logs_q->bind_param("i", $case_id); $logs_q->execute(); $logs = $logs_q->get_result()->fetch_all(MYSQLI_ASSOC);

// Fetch attachments
$att_q = $conn->prepare("SELECT original_name, stored_name, mime_type, uploaded_at FROM case_attachments WHERE case_id = ?");
$att_q->bind_param("i", $case_id); $att_q->execute(); $atts = $att_q->get_result()->fetch_all(MYSQLI_ASSOC);

include '../includes/header.php';
?>
<?php if($success): ?><div class="alert alert-success alert-dismissible fade show"><i class="bi bi-check-circle me-2"></i><?= htmlspecialchars($success) ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
<?php if($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h4 class="page-title mb-0"><i class="bi bi-search me-2"></i>Case #<?= $case_id ?> Investigation</h4>
    <a href="/threat_intel/expert/report.php?id=<?= $case_id ?>" class="btn btn-outline-dark btn-sm no-print" target="_blank"><i class="bi bi-printer me-1"></i>Print Report</a>
</div>

<div class="row">
<!-- LEFT COLUMN -->
<div class="col-lg-4">
    <!-- Case Info -->
    <div class="card mb-3">
        <div class="card-header bg-primary text-white"><i class="bi bi-info-circle me-1"></i>Case Info</div>
        <div class="card-body">
            <table class="table table-sm table-borderless mb-0 small">
                <tr><th>Title</th><td><?= htmlspecialchars($case['title']) ?></td></tr>
                <tr><th>Attack Type</th><td><?= htmlspecialchars($case['attack_type']) ?></td></tr>
                <tr><th>Reporter</th><td><?= htmlspecialchars($case['reporter']) ?></td></tr>
                <tr><th>Severity</th><td><span class="severity-badge severity-<?= $case['severity'] ?>"><?= $case['severity'] ?></span></td></tr>
                <tr><th>Score</th><td><strong><?= $case['severity_score'] ?></strong></td></tr>
                <tr><th>Status</th><td><span class="badge bg-secondary"><?= str_replace('_',' ',$case['status']) ?></span></td></tr>
                <tr><th>Filed</th><td><?= date('d M Y H:i', strtotime($case['created_at'])) ?></td></tr>
            </table>
        </div>
    </div>

    <!-- Update Status -->
    <div class="card mb-3">
        <div class="card-header bg-warning text-dark"><i class="bi bi-arrow-repeat me-1"></i>Update Status</div>
        <div class="card-body">
            <form method="POST">
                <input type="hidden" name="action" value="update_status">
                <select name="status" class="form-select form-select-sm mb-2">
                    <?php foreach(['open','in_progress','resolved','closed'] as $s): ?>
                    <option value="<?= $s ?>" <?= $case['status']===$s?'selected':'' ?>><?= ucfirst(str_replace('_',' ',$s)) ?></option>
                    <?php endforeach; ?>
                </select>
                <button class="btn btn-warning btn-sm w-100">Update Status</button>
            </form>
        </div>
    </div>

    <!-- MITRE -->
    <?php if ($case['mitre_name']): ?>
    <div class="card mb-3">
        <div class="card-header bg-dark text-white"><i class="bi bi-diagram-3 me-1"></i>MITRE ATT&CK</div>
        <div class="card-body small">
            <span class="badge bg-secondary mb-1"><?= htmlspecialchars($case['mitre_tid']) ?></span><br>
            <strong><?= htmlspecialchars($case['mitre_name']) ?></strong><br>
            <span class="text-muted">Tactic: <?= htmlspecialchars($case['mitre_tactic']) ?></span><br>
            <p class="mt-2 mb-0 text-muted"><?= htmlspecialchars($case['mitre_desc']) ?></p>
        </div>
    </div>
    <?php endif; ?>

    <!-- Attachments -->
    <?php if ($atts): ?>
    <div class="card mb-3">
        <div class="card-header bg-secondary text-white"><i class="bi bi-paperclip me-1"></i>Attachments</div>
        <div class="card-body small">
            <?php foreach($atts as $a): ?>
            <div class="mb-1"><i class="bi bi-file-earmark me-1"></i><?= htmlspecialchars($a['original_name']) ?> <span class="text-muted">(<?= date('d M', strtotime($a['uploaded_at'])) ?>)</span></div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>
</div>

<!-- RIGHT COLUMN -->
<div class="col-lg-8">
    <!-- Description -->
    <div class="card mb-3">
        <div class="card-header bg-primary text-white"><i class="bi bi-file-text me-1"></i>Incident Description</div>
        <div class="card-body"><p class="mb-0 small"><?= nl2br(htmlspecialchars($case['description'])) ?></p></div>
    </div>

    <!-- IOCs -->
    <?php if ($iocs): ?>
    <div class="card mb-3">
        <div class="card-header bg-danger text-white"><i class="bi bi-bug me-1"></i>Extracted IOCs (<?= count($iocs) ?>)</div>
        <div class="card-body">
            <?php foreach($iocs as $ioc): ?>
            <span class="ioc-tag">
                <span class="badge bg-secondary me-1" style="font-size:0.65rem"><?= $ioc['ioc_type'] ?></span>
                <?= htmlspecialchars($ioc['ioc_value']) ?>
                <?php if($ioc['is_confirmed']): ?><i class="bi bi-exclamation-triangle text-danger ms-1" title="Confirmed malicious"></i><?php endif; ?>
                <span class="text-muted ms-1">(seen <?= $ioc['times_seen'] ?>x)</span>
            </span>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- Rule Matches -->
    <?php if ($rules): ?>
    <div class="card mb-3">
        <div class="card-header bg-warning text-dark"><i class="bi bi-sliders me-1"></i>Rule Match Breakdown (Total Score: <?= $case['severity_score'] ?>)</div>
        <div class="card-body">
            <?php foreach($rules as $r): ?>
            <div class="rule-match-row">
                <strong><?= htmlspecialchars($r['name']) ?></strong>
                <span class="badge bg-danger float-end">+<?= $r['score_added'] ?> pts</span><br>
                <small class="text-muted">Matched keyword: <code><?= htmlspecialchars($r['matched_value']) ?></code></small>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- Add Note -->
    <div class="card mb-3">
        <div class="card-header bg-success text-white"><i class="bi bi-pencil me-1"></i>Add Investigation Note</div>
        <div class="card-body">
            <form method="POST">
                <input type="hidden" name="action" value="add_note">
                <textarea name="note" class="form-control mb-2" rows="3" placeholder="Document your findings, actions taken, or observations..."></textarea>
                <button class="btn btn-success btn-sm"><i class="bi bi-plus-circle me-1"></i>Add Note</button>
            </form>
        </div>
    </div>

    <!-- Audit Log -->
    <div class="card">
        <div class="card-header bg-secondary text-white"><i class="bi bi-journal-text me-1"></i>Case Audit Trail</div>
        <div class="card-body" style="max-height:300px;overflow-y:auto;">
            <?php foreach($logs as $log): ?>
            <div class="audit-log-item">
                <strong><?= htmlspecialchars(ucwords(str_replace('_',' ',$log['action']))) ?></strong>
                <?php if($log['full_name']): ?> &mdash; <em><?= htmlspecialchars($log['full_name']) ?></em><?php endif; ?>
                <span class="float-end text-muted" style="font-size:0.78rem"><?= date('d M Y H:i', strtotime($log['created_at'])) ?></span>
                <?php if($log['details']): ?><br><span class="text-secondary small"><?= htmlspecialchars($log['details']) ?></span><?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>
</div>
<?php include '../includes/footer.php'; ?>
