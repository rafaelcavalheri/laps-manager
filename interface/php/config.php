<?php

// Função para carregar variáveis do arquivo .env
if (!function_exists('loadEnvFile')) {
    function loadEnvFile($filePath) {
        if (!file_exists($filePath)) {
            return;
        }
        
        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            // Ignorar comentários e linhas vazias
            if (strpos(trim($line), '#') === 0 || empty(trim($line))) {
                continue;
            }
            
            // Verificar se a linha contém um sinal de igual
            if (strpos($line, '=') !== false) {
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                
                // Remover aspas se existirem
                if ((substr($value, 0, 1) === '"' && substr($value, -1) === '"') ||
                    (substr($value, 0, 1) === "'" && substr($value, -1) === "'")) {
                    $value = substr($value, 1, -1);
                }
                
                // Definir a variável de ambiente se não estiver definida
                if (!getenv($key)) {
                    putenv("$key=$value");
                }
            }
        }
    }
}

// Carregar variáveis do arquivo .env
loadEnvFile(__DIR__ . '/.env');

// Configurações do banco de dados - Lendo diretamente das variáveis de ambiente
$config = [
    'host' => getenv('DB_HOST') ?: 'db',
    'user' => getenv('DB_USER') ?: 'root',
    'password' => getenv('DB_PASSWORD') ?: '',
    'dbname' => getenv('DB_NAME') ?: 'laps',
    'glpi_url' => getenv('GLPI_URL') ?: 'https://glpi.exemplo.com',
    'ldap_allowed_groups' => getenv('LDAP_ALLOWED_GROUPS') ?: 'Domain Admins'
];

// Função para carregar configurações LDAP de forma segura
if (!function_exists('loadLdapSettings')) {
    function loadLdapSettings() {
        $ldapSettingsFile = __DIR__ . '/ldap_settings.php';

        // Inicializar variáveis LDAP com valores padrão
        $ldapServer = '';
        $ldapUser = '';
        $ldapBase = '';
        $ldapPassword = '';

        if (file_exists($ldapSettingsFile)) {
            // Definir constante de segurança antes de incluir (se não estiver definida)
            if (!defined('SECURE_ACCESS')) {
                define('SECURE_ACCESS', true);
            }

            // Capturar qualquer saída para evitar problemas de headers
            ob_start();
            include $ldapSettingsFile;
            ob_end_clean();
        }

        return [
            'server' => $ldapServer,
            'domain' => $ldapUser,
            'base_dn' => $ldapBase,
            'password' => $ldapPassword
        ];
    }
}

// Função de sanitização global
if (!function_exists('sanitizeInput')) {
    function sanitizeInput($input, $type = 'string') {
        if (is_array($input)) {
            return array_map(function($item) use ($type) {
                return sanitizeInput($item, $type);
            }, $input);
        }

        if (!is_string($input)) {
            return $input;
        }

        $input = trim($input);

        switch ($type) {
            case 'username':
                // Apenas letras, números, pontos, hífens e underscores
                return preg_replace('/[^a-zA-Z0-9._-]/', '', $input);
            case 'email':
                return filter_var($input, FILTER_SANITIZE_EMAIL);
            case 'url':
                return filter_var($input, FILTER_SANITIZE_URL);
            case 'int':
                return filter_var($input, FILTER_SANITIZE_NUMBER_INT);
            case 'float':
                return filter_var($input, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
            case 'html':
                // Remover tags HTML perigosas
                return strip_tags($input, '<p><br><strong><em><u><ol><ul><li>');
            case 'sql':
                // Para uso em prepared statements (não deve ser usado diretamente)
                return $input;
            default:
                // Sanitização padrão para strings
                return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        }
    }
}

// Função para sanitizar dados POST/GET
if (!function_exists('sanitizeRequestData')) {
    function sanitizeRequestData($data, $allowedFields = []) {
        $sanitized = [];

        foreach ($data as $key => $value) {
            // Se especificou campos permitidos, verificar se o campo está na lista
            if (!empty($allowedFields) && !in_array($key, $allowedFields)) {
                continue;
            }

            $sanitized[$key] = sanitizeInput($value);
        }

        return $sanitized;
    }
}

// Proteção CSRF
if (!function_exists('gerarTokenCsrf')) {
    function gerarTokenCsrf() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
}

if (!function_exists('validarTokenCsrf')) {
    function validarTokenCsrf($token) {
        return hash_equals($_SESSION['csrf_token'] ?? '', $token);
    }
}

if (!function_exists('verificarCsrf')) {
    function verificarCsrf($token) {
        if (!validarTokenCsrf($token)) {
            die('Erro: Token CSRF inválido.');
        }
    }
}

// Carregar configurações LDAP do arquivo separado
$config['ldap'] = loadLdapSettings();

return $config;
