<?php
require_once '../includes/session_check.php';
require_role(['platform_admin']);
require_once '../includes/db.php';
$page_title = 'Platform Admin Dashboard';

$conn->query("SELECT COUNT(*) FROM organizations")->bind_result ?? null;
$r = $conn->query("SELECT COUNT(*) c FROM organizations")->fetch_assoc(); $total_orgs = $r['c'];
$r = $conn->query("SELECT COUNT(*) c FROM cases")->fetch_assoc(); $total_cases = $r['c'];
$r = $conn->query("SELECT COUNT(*) c FROM iocs")->fetch_assoc(); $total_iocs = $r['c'];
$r = $conn->query("SELECT COUNT(*) c FROM alerts")->fetch_assoc(); $total_alerts = $r['c'];
$r = $conn->query("SELECT COUNT(*) c FROM users WHERE role != 'platform_admin'")->fetch_assoc(); $total_users = $r['c'];
$r = $conn->query("SELECT COUNT(*) c FROM iocs WHERE is_confirmed=1")->fetch_assoc(); $confirmed_iocs = $r['c'];

// Severity breakdown platform-wide
$sev_rows = $conn->query("SELECT severity, COUNT(*) cnt FROM cases GROUP BY severity")->fetch_all(MYSQLI_ASSOC);
$sev_map = array_column($sev_rows, 'cnt', 'severity');

// MITRE frequency
$mitre = $conn->query("SELECT m.technique_id, m.name, m.tactic, COUNT(c.id) cnt FROM cases c JOIN mitre_techniques m ON c.mitre_technique_id=m.id GROUP BY m.id ORDER BY cnt DESC LIMIT 8")->fetch_all(MYSQLI_ASSOC);

// Recent orgs
$recent_orgs = $conn->query("SELECT name, type, country, created_at FROM organizations ORDER BY created_at DESC LIMIT 5")->fetch_all(MYSQLI_ASSOC);

include '../includes/header.php';
?>
<h4 class="page-title"><i class="bi bi-house me-2"></i>Platform Admin Dashboard</h4>

<div class="row mb-4">
    <div class="col-md-2"><div class="stat-card bg-primary"><div class="stat-number"><?= $total_orgs ?></div><div class="stat-label"><i class="bi bi-building me-1"></i>Organizations</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-info"><div class="stat-number"><?= $total_cases ?></div><div class="stat-label"><i class="bi bi-folder me-1"></i>Total Cases</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-danger"><div class="stat-number"><?= $total_iocs ?></div><div class="stat-label"><i class="bi bi-globe me-1"></i>Global IOCs</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-warning text-dark"><div class="stat-number"><?= $confirmed_iocs ?></div><div class="stat-label"><i class="bi bi-exclamation-triangle me-1"></i>Confirmed IOCs</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-dark"><div class="stat-number"><?= $total_alerts ?></div><div class="stat-label"><i class="bi bi-bell me-1"></i>Alerts Generated</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-success"><div class="stat-number"><?= $total_users ?></div><div class="stat-label"><i class="bi bi-people me-1"></i>Platform Users</div></div></div>
</div>

<div class="row">
<div class="col-lg-6 mb-4">
    <!-- Severity Breakdown -->
    <div class="card mb-4">
        <div class="card-header bg-warning text-dark"><i class="bi bi-bar-chart me-1"></i>Platform-Wide Severity Breakdown</div>
        <div class="card-body">
            <?php foreach(['Critical'=>'danger','High'=>'warning','Medium'=>'info','Low'=>'success'] as $sev=>$col): ?>
            <div class="d-flex justify-content-between align-items-center mb-2">
                <span class="severity-badge severity-<?= $sev ?>"><?= $sev ?></span>
                <div class="flex-grow-1 mx-3">
                    <?php $cnt = $sev_map[$sev]??0; $pct = $total_cases>0?round(($cnt/$total_cases)*100):0; ?>
                    <div class="progress" style="height:18px;">
                        <div class="progress-bar bg-<?= $col ?>" style="width:<?= $pct ?>%"><?= $cnt ?></div>
                    </div>
                </div>
                <span class="text-muted small"><?= $pct ?>%</span>
            </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- Recent Orgs -->
    <div class="card">
        <div class="card-header bg-primary text-white d-flex justify-content-between">
            <span><i class="bi bi-building me-1"></i>Recent Organizations</span>
            <a href="/threat_intel/admin/organizations.php" class="btn btn-sm btn-light">View All</a>
        </div>
        <div class="card-body p-0">
            <table class="table table-hover mb-0 small">
                <thead><tr><th>Name</th><th>Type</th><th>Country</th><th>Joined</th></tr></thead>
                <tbody>
                <?php foreach($recent_orgs as $o): ?>
                <tr><td><?= htmlspecialchars($o['name']) ?></td><td><?= htmlspecialchars($o['type']) ?></td><td><?= htmlspecialchars($o['country']) ?></td><td><?= date('d M Y', strtotime($o['created_at'])) ?></td></tr>
                <?php endforeach; ?>
                <?php if(!$recent_orgs): ?><tr><td colspan="4" class="text-center text-muted py-3">No organizations yet.</td></tr><?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div class="col-lg-6 mb-4">
    <!-- MITRE Frequency -->
    <div class="card">
        <div class="card-header bg-dark text-white"><i class="bi bi-diagram-3 me-1"></i>Top MITRE ATT&CK Techniques</div>
        <div class="card-body p-0">
            <table class="table table-hover mb-0 small">
                <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Cases</th></tr></thead>
                <tbody>
                <?php foreach($mitre as $m): ?>
                <tr>
                    <td><span class="badge bg-dark"><?= htmlspecialchars($m['technique_id']) ?></span></td>
                    <td><?= htmlspecialchars($m['name']) ?></td>
                    <td><span class="badge bg-secondary"><?= htmlspecialchars($m['tactic']) ?></span></td>
                    <td><strong><?= $m['cnt'] ?></strong></td>
                </tr>
                <?php endforeach; ?>
                <?php if(!$mitre): ?><tr><td colspan="4" class="text-center text-muted py-3">No technique mappings yet.</td></tr><?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>
</div>
<?php include '../includes/footer.php'; ?>
