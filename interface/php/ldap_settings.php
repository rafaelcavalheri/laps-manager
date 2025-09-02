<?php
// Configurações LDAP - Gerado automaticamente
// Última atualização: 2025-07-29 19:21:13
// NOTA: Configurações do banco são carregadas do .env

// Configurações do MySQL (usando variáveis de ambiente de forma robusta)
$dbName = getenv('DB_NAME') ?: 'laps';
$dbUser = getenv('DB_USER') ?: 'root';
$dbPass = getenv('DB_PASSWORD') ?: '';
$dbHost = getenv('DB_HOST') ?: 'db';

// Configurações do LDAP (usando variáveis de ambiente de forma robusta)
$ldapServer = getenv('LDAP_SERVER') ?: 'ldap://seu-servidor-ldap.local';
$ldapUser = getenv('LDAP_USER') ?: 'CN=usuario-laps,OU=TI,DC=exemplo,DC=local';
$ldapBase = getenv('LDAP_BASE') ?: 'dc=exemplo,dc=local';
$ldapPassword = getenv('LDAP_PASSWORD') ?: '';
