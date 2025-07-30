#!/bin/bash

# Arquivo de configuração
CONFIG_FILE="/var/www/html/ldap_settings.php"

# Função para carregar configurações do arquivo
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # Executar o arquivo PHP e capturar as variáveis
        DB_NAME=$(/usr/local/bin/php -r "require_once '$CONFIG_FILE'; echo \$dbName;")
        DB_USER=$(/usr/local/bin/php -r "require_once '$CONFIG_FILE'; echo \$dbUser;")
        DB_PASS=$(/usr/local/bin/php -r "require_once '$CONFIG_FILE'; echo \$dbPass;")
        DB_HOST=$(/usr/local/bin/php -r "require_once '$CONFIG_FILE'; echo \$dbHost;")
    else
        echo "Arquivo de configuração $CONFIG_FILE não encontrado."
        exit 1
    fi
}

# Carrega as configurações
load_config

echo "=== ESTATÍSTICAS DO SISTEMA LAPS ==="
echo "Data/Hora: $(date)"
echo ""

# Estatísticas gerais
echo "📊 ESTATÍSTICAS GERAIS:"
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT
    'Total de computadores com senha' as Descricao,
    COUNT(*) as Quantidade
FROM Passwords
UNION ALL
SELECT
    'Total de computadores sem senha' as Descricao,
    COUNT(*) as Quantidade
FROM null_passwords
UNION ALL
SELECT
    'Total de senhas no histórico' as Descricao,
    COUNT(*) as Quantidade
FROM old_passwords
UNION ALL
SELECT
    'Total geral de computadores' as Descricao,
    (SELECT COUNT(*) FROM Passwords) + (SELECT COUNT(*) FROM null_passwords) as Quantidade;
" 2>/dev/null

echo ""
echo "📅 COMPUTADORES POR DATA DE EXPORTAÇÃO:"
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT
    export_date as 'Data de Exportação',
    COUNT(*) as 'Quantidade de Computadores'
FROM Passwords
WHERE export_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
GROUP BY export_date
ORDER BY export_date DESC;
" 2>/dev/null

echo ""
echo "🔄 COMPUTADORES ATUALIZADOS RECENTEMENTE:"
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT
    ComputerName as 'Nome do Computador',
    DATE(updated_at) as 'Data de Atualização',
    export_date as 'Data de Exportação'
FROM Passwords
WHERE updated_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY updated_at DESC
LIMIT 10;
" 2>/dev/null

echo ""
echo "⏰ SENHAS EXPIRANDO EM BREVE:"
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT
    ComputerName as 'Nome do Computador',
    ExpirationTimestamp as 'Data de Expiração',
    DATEDIFF(ExpirationTimestamp, CURDATE()) as 'Dias Restantes'
FROM Passwords
WHERE ExpirationTimestamp BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)
ORDER BY ExpirationTimestamp ASC
LIMIT 10;
" 2>/dev/null

echo ""
echo "📈 ESTATÍSTICAS DE PROCESSAMENTO (ÚLTIMAS 24H):"
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT
    'Computadores atualizados hoje' as Descricao,
    COUNT(*) as Quantidade
FROM Passwords
WHERE DATE(updated_at) = CURDATE()
UNION ALL
SELECT
    'Novos computadores hoje' as Descricao,
    COUNT(*) as Quantidade
FROM Passwords
WHERE DATE(created_at) = CURDATE()
UNION ALL
SELECT
    'Computadores sem senha adicionados hoje' as Descricao,
    COUNT(*) as Quantidade
FROM null_passwords
WHERE DATE(created_at) = CURDATE();
" 2>/dev/null

echo ""
echo "=== FIM DAS ESTATÍSTICAS ==="