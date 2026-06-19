<?php
require_once '../includes/session_check.php';
require_role(['employee']);
require_once '../includes/db.php';
require_once '../engine/ThreatEngine.php';
$page_title = 'File Complaint';
$error = '';
$success = '';

$attack_types = ['Phishing','Ransomware','Malware','Data Breach','Brute Force','SQL Injection','DDoS','Unauthorized Access','Insider Threat','Social Engineering','Zero Day Exploit','Other'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title       = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $attack_type = trim($_POST['attack_type'] ?? '');

    if (!$title || !$description || !$attack_type) {
        $error = 'Title, description, and attack type are required.';
    } else {
        $uid = $_SESSION['user_id'];
        $oid = $_SESSION['org_id'];

        // Insert case
        $stmt = $conn->prepare("INSERT INTO cases (org_id, title, description, attack_type, reported_by) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("isssi", $oid, $title, $description, $attack_type, $uid);
        $stmt->execute();
        $case_id = $conn->insert_id;

        // Handle file attachment
        if (!empty($_FILES['attachment']['name'])) {
            $allowed_mime = ['image/jpeg','image/png','image/gif','application/pdf','text/plain','text/csv'];
            $file_mime = mime_content_type($_FILES['attachment']['tmp_name']);
            if (!in_array($file_mime, $allowed_mime)) {
                $error = 'Invalid file type. Allowed: JPG, PNG, PDF, TXT, CSV.';
            } else {
                $orig_name   = basename($_FILES['attachment']['name']);
                $stored_name = uniqid('att_', true) . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '', $orig_name);
                $upload_dir  = __DIR__ . '/../uploads/';
                if (!is_dir($upload_dir)) mkdir($upload_dir, 0755, true);
                move_uploaded_file($_FILES['attachment']['tmp_name'], $upload_dir . $stored_name);
                $att = $conn->prepare("INSERT INTO case_attachments (case_id, uploaded_by, original_name, stored_name, mime_type) VALUES (?, ?, ?, ?, ?)");
                $att->bind_param("iisss", $case_id, $uid, $orig_name, $stored_name, $file_mime);
                $att->execute();
            }
        }

        // Case creation audit log
        $log = $conn->prepare("INSERT INTO case_logs (case_id, user_id, action, details) VALUES (?, ?, 'case_created', ?)");
        $detail = "Case filed by employee. Attack type: $attack_type";
        $log->bind_param("iis", $case_id, $uid, $detail);
        $log->execute();

        // Run rule-based engine
        $engine = new ThreatEngine($conn);
        $engine->analyze($case_id, $oid, $description);

        // Log engine run
        $score = $engine->getScore();
        $sev   = $engine->getSeverity();
        $ioc_count = count($engine->getIOCs());
        $logd = "Engine analysis complete. Score: $score, Severity: $sev, IOCs extracted: $ioc_count";
        $elog = $conn->prepare("INSERT INTO case_logs (case_id, user_id, action, details) VALUES (?, NULL, 'engine_analysis', ?)");
        $elog->bind_param("is", $case_id, $logd);
        $elog->execute();

        header("Location: /threat_intel/employee/case_view.php?id=$case_id&new=1");
        exit();
    }
}

include '../includes/header.php';
?>
<h4 class="page-title"><i class="bi bi-plus-circle me-2"></i>File Incident Complaint</h4>
<div class="row justify-content-center">
<div class="col-lg-8">
<div class="card">
    <div class="card-header bg-primary text-white"><i class="bi bi-shield-exclamation me-2"></i>New Incident Report</div>
    <div class="card-body p-4">
        <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="POST" enctype="multipart/form-data" novalidate>
            <div class="mb-3">
                <label class="form-label fw-semibold">Incident Title <span class="text-danger">*</span></label>
                <input type="text" name="title" class="form-control" maxlength="255" required placeholder="Brief description of the incident" value="<?= htmlspecialchars($_POST['title'] ?? '') ?>">
            </div>
            <div class="mb-3">
                <label class="form-label fw-semibold">Attack Type <span class="text-danger">*</span></label>
                <select name="attack_type" class="form-select" required>
                    <option value="">-- Select attack type --</option>
                    <?php foreach ($attack_types as $t): ?>
                    <option value="<?= $t ?>" <?= ($_POST['attack_type'] ?? '') === $t ? 'selected' : '' ?>><?= $t ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label fw-semibold">Incident Description <span class="text-danger">*</span></label>
                <textarea name="description" class="form-control" rows="7" required placeholder="Describe the incident in detail. Include any suspicious IPs, domains, email addresses, or file hashes you observed. The more detail you provide the better the automated analysis will be."><?= htmlspecialchars($_POST['description'] ?? '') ?></textarea>
                <div class="form-text">Tip: Include any suspicious IPs, domains, URLs, emails, or file hashes — they will be automatically extracted and analyzed.</div>
            </div>
            <div class="mb-4">
                <label class="form-label fw-semibold">Attachment <span class="text-muted">(optional)</span></label>
                <input type="file" name="attachment" class="form-control" accept=".jpg,.jpeg,.png,.pdf,.txt,.csv">
                <div class="form-text">Allowed: JPG, PNG, PDF, TXT, CSV. Max 10MB.</div>
            </div>
            <div class="d-flex gap-2">
                <button type="submit" class="btn btn-primary fw-bold"><i class="bi bi-send me-2"></i>Submit Complaint</button>
                <a href="/threat_intel/employee/dashboard.php" class="btn btn-outline-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>
</div>
</div>
<?php include '../includes/footer.php'; ?>
