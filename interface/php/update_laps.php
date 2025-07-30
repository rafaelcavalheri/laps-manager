<?php
// VERSÃO FINAL OTIMIZADA - 2024-07-31

// Headers de segurança
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

// Inicia a sessão se necessário
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Carrega a configuração e funções CSRF
require_once __DIR__ . '/config.php';

// Validação de autenticação
if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    http_response_code(403);
    die("Acesso negado: não autenticado.");
}

// Validação do token CSRF
if (!isset($_POST['csrf_token']) || !validarTokenCsrf($_POST['csrf_token'])) {
    http_response_code(403);
    die("Token CSRF inválido.");
}

try {
    // Define o comando final e otimizado.
    // O 'nohup' garante que o script continue rodando mesmo que a conexão seja fechada.
    // O '>' redireciona a saída padrão para o "buraco negro" (/dev/null).
    // O '2>&1' redireciona a saída de erro para o mesmo lugar.
    // O '&' no final executa o comando em segundo plano, liberando o PHP imediatamente.
    $command = sprintf(
        'nohup bash -c "export DB_HOST=%s; export DB_NAME=%s; export DB_USER=%s; export DB_PASSWORD=%s; export LDAP_SERVER=%s; export LDAP_USER=%s; export LDAP_BASE=%s; export LDAP_PASSWORD=%s; /usr/local/bin/ldap-up.sh" > /dev/null 2>&1 &',
        escapeshellarg(getenv('DB_HOST')),
        escapeshellarg(getenv('DB_NAME')),
        escapeshellarg(getenv('DB_USER')),
        escapeshellarg(getenv('DB_PASSWORD')),
        escapeshellarg(getenv('LDAP_SERVER')),
        escapeshellarg(getenv('LDAP_USER')),
        escapeshellarg(getenv('LDAP_BASE')),
        escapeshellarg(getenv('LDAP_PASSWORD'))
    );
    
    // Executa o comando em segundo plano
    shell_exec($command);
    
    // Responde imediatamente ao front-end com sucesso
    echo "Processo de atualização iniciado em segundo plano com sucesso.";

} catch (Exception $e) {
    // Captura qualquer exceção
    error_log("ERRO CRÍTICO em update_laps.php: " . $e->getMessage());
    http_response_code(500); // Erro Interno do Servidor
    echo "Ocorreu um erro crítico no servidor ao tentar iniciar o script de atualização.";
}