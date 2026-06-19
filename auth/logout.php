<?php
session_start();
session_destroy();
header("Location: /threat_intel/auth/login.php");
exit();
?>
