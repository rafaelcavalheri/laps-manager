<?php
// Headers de segurança
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Log de logout
$username = $_SESSION['username'] ?? 'unknown';
$userIP = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$sessionId = session_id();

$logMessage = sprintf(
    "SECURITY: User logout - User: %s, IP: %s, Session: %s, Time: %s",
    $username,
    $userIP,
    $sessionId,
    date('Y-m-d H:i:s')
);
error_log($logMessage);

// Destruir todas as variáveis de sessão
$_SESSION = array();

// Se desejar destruir a sessão completamente, apague também o cookie de sessão
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Finalmente, destruir a sessão
session_destroy();

// Redirecionar para a página de login
header("Location: index.php");
exit();
?>