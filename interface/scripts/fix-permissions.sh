#!/bin/bash

# Script para corrigir permissões do arquivo ldap_settings.php
# Este script é executado durante a inicialização do container

echo "Corrigindo permissões do arquivo ldap_settings.php..."

# Garante que o arquivo ldap_settings.php tenha as permissões corretas
if [ -f /var/www/html/ldap_settings.php ]; then
    chown www-data:www-data /var/www/html/ldap_settings.php
    chmod 664 /var/www/html/ldap_settings.php
    echo "Permissões do ldap_settings.php corrigidas com sucesso"
else
    echo "Arquivo ldap_settings.php não encontrado"
fi

# Garante que o diretório /var/www/html tenha as permissões corretas
chown -R www-data:www-data /var/www/html
echo "Permissões do diretório /var/www/html corrigidas"