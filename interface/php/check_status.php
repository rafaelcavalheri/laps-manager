<?php
// check_status.php

header("Content-Type: application/json");

// Medidas de segurança básicas
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Acesso negado.']);
    exit();
}

$logFile = '/var/log/ldap-up.log';
$response = ['status' => 'running', 'message' => 'Processo em andamento...'];

if (file_exists($logFile)) {
    // Lê a última linha do arquivo de log
    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $lastLine = $lines ? end($lines) : '';

    if (strpos($lastLine, 'Processo concluído com sucesso') !== false) {
        $response = ['status' => 'completed', 'message' => 'Atualização concluída com sucesso!'];
    } elseif (strpos($lastLine, 'ERRO:') !== false) {
        $response = ['status' => 'error', 'message' => 'Ocorreu um erro durante a atualização. Verifique os logs.'];
    } else {
        // Se não encontrou "concluído" ou "erro", assume que está rodando.
        // Pega a última mensagem para dar um feedback mais detalhado.
        $response['message'] = $lastLine;
    }
} else {
    $response = ['status' => 'pending', 'message' => 'Aguardando início do processo...'];
}

echo json_encode($response);
