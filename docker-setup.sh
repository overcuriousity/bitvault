#!/bin/bash

# Check if wget is installed; if not, try to use curl
if ! command -v wget &> /dev/null
then
    download_command="curl -O"
else
    download_command="wget"
fi

# Get installation directory from user
echo -e "\033[1mEnter installation directory (default is /usr/share/bitvault):\033[0m"
read install_dir
install_dir=${install_dir:-/usr/share/bitvault}

# Create directory and download files
mkdir -p $install_dir
cd $install_dir
$download_command https://raw.githubusercontent.com/overcuriousity/bitvault/master/.env
$download_command https://raw.githubusercontent.com/overcuriousity/bitvault/master/compose.yaml

# Get public path URL and port from user
echo -e "\033[1mEnter public path URL (e.g. https://bitvault.myserver.net or http://localhost:8080):\033[0m"
read public_path

echo -e "\033[1mEnter port number (default is 8080):\033[0m"
read port
port=${port:-8080}

# Update environment variables in .env file
sed -i "s|BITVAULT_PUBLIC_PATH=.*|BITVAULT_PUBLIC_PATH=${public_path}|" .env
sed -i "s|BITVAULT_PORT=.*|BITVAULT_PORT=${port}|" .env

# Start BitVault using Docker Compose
# Data is stored in a named Docker volume (bitvault_data).
# To use a bind-mount instead, edit compose.yaml and pre-create the directory:
#   mkdir -p $install_dir/bitvault-data && chown 65532:65532 $install_dir/bitvault-data
docker compose --env-file .env up --detach
