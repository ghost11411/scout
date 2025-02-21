#!/bin/bash

# VARS
RESET="\e[0m"
OKBOLD="\033[01;01m"
OKRED="\033[0;31m"
OKGREEN="\033[0;32m"
OKBLUE="\033[1;34m"

#CHECK ROOT
echo 
echo -e "${OKBLUE} Checking Root Permissions ${RESET}"
sleep 2
if [ "$EUID" -ne 0 ];then 
    echo -e "${OKRED} !!Please run as root (use sudo ./install.sh)!! ${RESET}"
exit
else
    echo -e "${OKGREEN} **Root Permission Granted** ${RESET}"
fi
echo

INSTALL_DIR=~/scout

echo -e "${OKBOLD}${OKBLUE}[This script will uninstall scout and remove ALL files under $INSTALL_DIR. Are you sure you want to continue?"
read -p "(Y/N): " answer

if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    sudo rm -Rf ~/scout/
    clear
    echo -e "${OKBOLD}${OKGREEN}[ Removed ]${RESET}"
else 
    echo -e "${OKBOLD}${OKRED}[ Not Removed ]${RESET}"
fi
