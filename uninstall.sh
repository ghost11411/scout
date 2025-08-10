#!/bin/bash
# VARS
RESET="\e[0m"
BOLD="\033[01;01m"
RED="\033[0;31m"
GREEN="\033[0;32m"
BLUE="\033[1;34m"

INSTALL_DIR=~/scout

#CHECK ROOT
echo 
echo -e "${BLUE}Checking Root Permissions ${RESET}"
sleep 0.5
if [ "$EUID" -ne 0 ];then 
    echo -e "${BOLD}${RED}!!Please run as root (sudo ./uninstall.sh)!! ${RESET}"
exit
else
    echo -e "${GREEN} **Root Permission Granted** ${RESET}"
fi
echo

echo -e "${BOLD}${BLUE}[This script will uninstall scout and remove ALL files under $INSTALL_DIR. Are you sure you want to continue?"
read -p "(Y/N): " answer

if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    sudo rm -Rf ~/scout/
    clear
    echo -e "${BOLD}${GREEN}[Scout is Removed]${RESET}"
else 
    clear
    echo -e "${BOLD}${RED}[ Scout is Not Removed ]${RESET}"
fi
