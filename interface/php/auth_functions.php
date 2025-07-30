<?php

function authenticateADUser($username, $password, $config = null) {

    // Se não foi passada configuração, carrega do config.php
    if ($config === null) {
        $config = include __DIR__ . '/config.php';
    }

    // Verifica se a configuração LDAP existe e está válida
    if (!isset($config['ldap']) ||
        !is_array($config['ldap']) ||
        !isset($config['ldap']['server']) ||
        empty($config['ldap']['server']) ||
        !isset($config['ldap']['domain']) ||
        empty($config['ldap']['domain']) ||
        !isset($config['ldap']['base_dn']) ||
        empty($config['ldap']['base_dn'])) {
        error_log("Configuração LDAP incompleta ou não configurada");
        return "Sistema LDAP não configurado. Entre em contato com o administrador.";
    }

    // Verifica se a extensão LDAP está carregada
    if (!function_exists('ldap_connect')) {
        error_log("Extensão LDAP não está instalada no PHP");
        return "Erro de configuração do sistema";
    }

    // Conexão LDAP
    $ldapConn = ldap_connect($config['ldap']['server']);
    if (!$ldapConn) {
        error_log("Falha ao conectar ao servidor LDAP: " . $config['ldap']['server']);
        return "Erro de conexão com o servidor";
    }

    // Configurações LDAP
    ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, 0);

    // Extrair o domínio do DN do usuário LDAP
    $domain = '';
    if (preg_match('/DC=([^,]+),DC=([^,]+)/', $config['ldap']['domain'], $matches)) {
        $domain = $matches[1] . '.' . $matches[2];
    }

    // Tenta autenticar com formato username@domain
    $ldapBind = @ldap_bind($ldapConn, "$username@$domain", $password);
    if (!$ldapBind) {
        $ldapError = ldap_error($ldapConn);
        error_log("Falha na autenticação LDAP para $username@$domain: $ldapError");
        return "Usuário ou senha inválidos";
    }

    // Busca informações do usuário
    $searchFilter = "(sAMAccountName=$username)";
    $attributes = ["memberof", "displayname"];
    $search = ldap_search($ldapConn, $config['ldap']['base_dn'], $searchFilter, $attributes);

    if (!$search) {
        error_log("Falha na busca LDAP: " . ldap_error($ldapConn));
        ldap_unbind($ldapConn);
        return "Erro ao verificar permissões";
    }

    $entries = ldap_get_entries($ldapConn, $search);
    if ($entries['count'] == 0) {
        error_log("Usuário não encontrado no AD: $username");
        ldap_unbind($ldapConn);
        return "Usuário não encontrado no diretório";
    }

    // Verifica se o atributo memberof existe para este usuário
    $isAuthorized = false;
    if (isset($entries[0]['memberof'])) {
        $userGroups = $entries[0]['memberof'];

        if (is_array($userGroups)) {
            foreach ($userGroups as $group) {
                if (!is_numeric($group)) { // Ignora índices numéricos
                    if (stripos($group, 'CN=STI,') !== false || stripos($group, 'CN=Domain Admins,') !== false) {
                        $isAuthorized = true;
                        break;
                    }
                }
            }
        }
    }

    ldap_unbind($ldapConn);

    if (!$isAuthorized) {
        error_log("Usuário $username não tem permissão para acessar o sistema");
        return "Usuário sem permissão para acessar o sistema";
    }

    return true;
}

?>
