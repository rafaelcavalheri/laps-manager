#!/bin/bash

# Arquivo de log
LOG_FILE="/var/log/ldap-up.log"

# Limpa o log antigo para uma nova depuração
> "$LOG_FILE"

# Função para registrar logs
log() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" >> "$LOG_FILE"
}

# As variáveis (DB_*, LDAP_*) são injetadas pelo comando que chama este script.
# Este script confia que o ambiente de execução já contém as variáveis necessárias.

# Função para decodificar Base64
decode_base64() {
    echo "$1" | base64 -d 2>/dev/null
}

# Inicia o log
log "Iniciando execução do script ldap-up.sh (versão final com variáveis de ambiente)"
log "DB_HOST: $DB_HOST, DB_NAME: $DB_NAME, DB_USER: $DB_USER"
log "LDAP_SERVER: $LDAP_SERVER"

# Exporta a senha do banco de dados para a variável de ambiente que o mysql-client lê.
export MYSQL_PWD="$DB_PASSWORD"

# Cria a tabela temporária
mysql -h "$DB_HOST" -u "$DB_USER" "$DB_NAME" <<EOF
DROP TABLE IF EXISTS TempPasswords;
CREATE TABLE TempPasswords (
    ComputerName VARCHAR(255),
    Password VARCHAR(255),
    ExpirationTimestamp DATE
);
EOF

# Verifica o status do último comando
if [ $? -ne 0 ]; then
    log "ERRO: Falha ao criar a tabela temporária. Verifique as credenciais do banco e a conexão."
    exit 1
fi

# Executa o comando ldapsearch - busca computadores COM senha LAPS
TEMP_LDAP_FILE=$(mktemp)
ldapsearch -H "$LDAP_SERVER" -D "$LDAP_USER" -w "$LDAP_PASSWORD" -b "$LDAP_BASE" -E pr=1000/noprompt "(objectCategory=computer)" dNSHostName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime > "$TEMP_LDAP_FILE"

# Executa o comando ldapsearch - busca TODOS os computadores
TEMP_LDAP_FILE_ALL=$(mktemp)
ldapsearch -H "$LDAP_SERVER" -D "$LDAP_USER" -w "$LDAP_PASSWORD" -b "$LDAP_BASE" -E pr=1000/noprompt "(objectCategory=computer)" dNSHostName > "$TEMP_LDAP_FILE_ALL"

# Processa a saída do LDAP
TEMP_FILE=$(mktemp)
TEMP_FILE_NO_PASSWORD=$(mktemp)

# Primeiro, extrai todos os computadores que têm senha LAPS
declare -A COMPUTERS_WITH_PASSWORD
declare -A COMPUTERS_EXPIRATION

while read -r line; do
    if [[ "$line" =~ ^dn:: ]]; then
        COMPUTER_NAME=$(decode_base64 "${line#dn:: }" | awk -F"," '{print $1}' | awk -F"=" '{print $2}')
    elif [[ "$line" =~ ^dn: ]]; then
        COMPUTER_NAME=$(echo "$line" | awk -F"," '{print $1}' | awk -F"=" '{print $2}')
    fi

    if [[ "$line" =~ ^ms-Mcs-AdmPwd: ]]; then
        ADMIN_PASSWORD=$(echo "$line" | awk '{print $2}')
        if [[ -n "$COMPUTER_NAME" && -n "$ADMIN_PASSWORD" ]]; then
            COMPUTERS_WITH_PASSWORD["$COMPUTER_NAME"]="$ADMIN_PASSWORD"
        fi
    fi

    if [[ "$line" =~ ^ms-Mcs-AdmPwdExpirationTime: ]]; then
        EXPIRATION_TIMESTAMP=$(echo "$line" | awk '{print $2}')
        if [[ -n "$EXPIRATION_TIMESTAMP" && "$EXPIRATION_TIMESTAMP" != "0" ]]; then
            EXPIRATION_DATE=$(date -d "@$(($EXPIRATION_TIMESTAMP / 10000000 - 11644473600))" +"%Y-%m-%d" 2>/dev/null || echo "NULL")
        else
            EXPIRATION_DATE="NULL"
        fi
        if [[ -n "$COMPUTER_NAME" && -n "$EXPIRATION_TIMESTAMP" ]]; then
            COMPUTERS_EXPIRATION["$COMPUTER_NAME"]="$EXPIRATION_DATE"
        fi
    fi
done < "$TEMP_LDAP_FILE"

# Agora processa todos os computadores
while read -r line; do
    if [[ "$line" =~ ^dn:: ]]; then
        COMPUTER_NAME=$(decode_base64 "${line#dn:: }" | awk -F"," '{print $1}' | awk -F"=" '{print $2}')
    elif [[ "$line" =~ ^dn: ]]; then
        COMPUTER_NAME=$(echo "$line" | awk -F"," '{print $1}' | awk -F"=" '{print $2}')
    fi

    # Se encontrou um computador
    if [[ -n "$COMPUTER_NAME" ]]; then
        # Verifica se tem senha
        if [[ -n "${COMPUTERS_WITH_PASSWORD[$COMPUTER_NAME]}" ]]; then
            # Computador COM senha
            EXPIRATION_DATE="${COMPUTERS_EXPIRATION[$COMPUTER_NAME]:-NULL}"
            echo "'$COMPUTER_NAME','${COMPUTERS_WITH_PASSWORD[$COMPUTER_NAME]}','$EXPIRATION_DATE'" >> "$TEMP_FILE"
        else
            # Computador SEM senha
            echo "'$COMPUTER_NAME','',NULL" >> "$TEMP_FILE_NO_PASSWORD"
        fi
    fi
done < "$TEMP_LDAP_FILE_ALL"

# Carrega dados temporários (computadores COM senha)
if [[ -s "$TEMP_FILE" ]]; then
    mysql -h "$DB_HOST" -u "$DB_USER" "$DB_NAME" <<EOF
LOAD DATA LOCAL INFILE '$TEMP_FILE'
INTO TABLE TempPasswords
FIELDS TERMINATED BY ',' ENCLOSED BY "'"
(ComputerName, Password, ExpirationTimestamp);
EOF
fi

# Carrega dados temporários (computadores SEM senha)
if [[ -s "$TEMP_FILE_NO_PASSWORD" ]]; then
    mysql -h "$DB_HOST" -u "$DB_USER" "$DB_NAME" <<EOF
LOAD DATA LOCAL INFILE '$TEMP_FILE_NO_PASSWORD'
INTO TABLE TempPasswords
FIELDS TERMINATED BY ',' ENCLOSED BY "'"
(ComputerName, Password, ExpirationTimestamp);
EOF
fi

# Remove arquivos temporários
rm -f "$TEMP_LDAP_FILE" "$TEMP_LDAP_FILE_ALL" "$TEMP_FILE" "$TEMP_FILE_NO_PASSWORD"

# Atualiza o banco de dados
mysql -h "$DB_HOST" -u "$DB_USER" "$DB_NAME" <<EOF

-- 1. Limpa ManualPassword APENAS se houver nova senha do LAPS (diferente da atual)
UPDATE Passwords p
JOIN TempPasswords t ON p.ComputerName = t.ComputerName
SET p.ManualPassword = NULL
WHERE p.Password != t.Password 
  AND t.Password IS NOT NULL 
  AND t.Password != '';

UPDATE old_passwords op
JOIN TempPasswords t ON op.ComputerName = t.ComputerName
SET op.ManualPassword = NULL
WHERE op.Password != t.Password 
  AND t.Password IS NOT NULL 
  AND t.Password != '';

UPDATE null_passwords np
JOIN TempPasswords t ON np.ComputerName = t.ComputerName
SET np.ManualPassword = NULL
WHERE np.Password != t.Password 
  AND t.Password IS NOT NULL 
  AND t.Password != '';

-- 2. Move senhas antigas para o histórico (APENAS se a senha mudou e não existe no histórico)
INSERT IGNORE INTO old_passwords (ComputerName, Password, ExpirationTimestamp)
SELECT p.ComputerName, p.Password, p.ExpirationTimestamp
FROM Passwords p
INNER JOIN TempPasswords t ON p.ComputerName = t.ComputerName
WHERE t.Password IS NOT NULL 
  AND t.Password != ''
  AND p.Password != t.Password
  AND p.Password != ''  -- Evita mover senhas vazias
  AND NOT EXISTS (
    SELECT 1 FROM old_passwords op 
    WHERE op.ComputerName = p.ComputerName 
      AND op.Password = p.Password
  );

-- 3. INSERÇÃO PRINCIPAL CORRIGIDA - Insere/atualiza todos os computadores com senha
INSERT INTO Passwords (ComputerName, Password, ExpirationTimestamp, export_date)
SELECT DISTINCT t.ComputerName, t.Password, t.ExpirationTimestamp, CURDATE()
FROM TempPasswords t
WHERE t.Password IS NOT NULL 
  AND t.Password != ''
ON DUPLICATE KEY UPDATE 
    Password = VALUES(Password),
    ExpirationTimestamp = VALUES(ExpirationTimestamp),
    updated_at = CURRENT_TIMESTAMP,
    export_date = CURDATE();

-- 4. Remove computadores da tabela null_passwords se agora têm senha
DELETE FROM null_passwords 
WHERE ComputerName IN (
    SELECT ComputerName 
    FROM TempPasswords 
    WHERE Password IS NOT NULL 
      AND Password != ''
);

-- 5. INSERE COMPUTADORES SEM SENHA NA TABELA null_passwords (APENAS se não existem)
INSERT IGNORE INTO null_passwords (ComputerName, Password, ExpirationTimestamp)
SELECT t.ComputerName, t.Password, t.ExpirationTimestamp
FROM TempPasswords t
WHERE (t.Password IS NULL OR t.Password = '')
  AND NOT EXISTS (SELECT 1 FROM null_passwords np WHERE np.ComputerName = t.ComputerName)
  AND NOT EXISTS (SELECT 1 FROM Passwords p WHERE p.ComputerName = t.ComputerName);

-- 6. Atualiza export_date para computadores que não foram processados (SEM alterar updated_at)
UPDATE Passwords 
SET export_date = CURDATE()
WHERE ComputerName NOT IN (
    SELECT ComputerName 
    FROM TempPasswords
)
AND export_date != CURDATE();

-- 7. Limpeza de registros antigos (mantém apenas 5 meses)
DELETE FROM Passwords 
WHERE export_date < DATE_SUB(CURDATE(), INTERVAL 5 MONTH);

-- 8. Limpeza do histórico (remove duplicações e mantém apenas registros únicos)
DELETE op1 FROM old_passwords op1
INNER JOIN old_passwords op2 
WHERE op1.id > op2.id 
  AND op1.ComputerName = op2.ComputerName 
  AND op1.Password = op2.Password;

-- Mantém apenas a senha mais recente por computador (baseado na data de expiração)
DELETE FROM old_passwords 
WHERE id NOT IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (PARTITION BY ComputerName ORDER BY ExpirationTimestamp DESC, created_at DESC) as rn
        FROM old_passwords
    ) AS ranked_old_passwords 
    WHERE rn <= 1
);

-- 9. Limpa tabela temporária
TRUNCATE TABLE TempPasswords;

EOF

# Finaliza o log
log "Processo concluído com sucesso."
