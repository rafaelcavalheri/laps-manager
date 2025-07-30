#!/bin/bash

# Aguarda o banco de dados estar pronto
echo "Aguardando banco de dados..."
sleep 10

# Cria usuário personalizado se necessário
if [ -f /usr/local/bin/create-user.sh ]; then
    /usr/local/bin/create-user.sh
fi

# Inicia o Apache em segundo plano
service apache2 start

# Salva as variáveis de ambiente para o cron
env | grep -E "^(DB_|LDAP_|TZ=)" > /etc/environment

# Inicia o cron em primeiro plano
cron -f 