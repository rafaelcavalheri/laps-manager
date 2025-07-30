<?php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Carregar configuração centralizada
global $config;
if (!isset($config)) {
    $config = include 'config.php';
}

// Inclui o sistema de autenticação
require_once 'auth_functions.php';
require_once 'local_auth.php';

// Verifica se o formulário foi enviado
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Tenta autenticar no AD primeiro
    $authResult = authenticateADUser($username, $password, $config);

    if ($authResult === true) {
        // Login LDAP bem-sucedido
        $_SESSION['username'] = $username;
        $_SESSION['authenticated'] = true;
        $_SESSION['auth_type'] = 'ldap';
        header("Location: dashboard.php");
        exit();
    } else {
        // Se falhar no LDAP, tenta autenticação local
        if (authenticateLocalUser($username, $password)) {
            // Login local bem-sucedido
            $_SESSION['username'] = $username;
            $_SESSION['authenticated'] = true;
            $_SESSION['auth_type'] = 'local';
            header("Location: dashboard.php");
            exit();
        } else {
            // Falha em ambos os métodos
            $error = "Falha na autenticação. Verifique suas credenciais.";
            header("Location: index.php?error=" . urlencode($error));
            exit();
        }
    }
}

?>
