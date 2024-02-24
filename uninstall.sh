#!/bin/bash

# VARS
RESET=$(tput sgr0)
OKBOLD=$(tput bold)
OKRED=$(tput setaf 1)
OKGREEN=$(tput setaf 2)
OKBLUE=$(tput setaf 4)

echo -e "$OKBOLD$OKRED" 
    echo -e "                      _   "
    echo -e "                     | |  "
    echo -e "  ___  ___ ___  _   _| |_ "
    echo -e " / __|/ __/ _ \| | | | __|"
    echo -e " \__ \ (_| (_) | |_| | |_ "
    echo -e " |___/\___\___/ \__,_|\__|"
    echo -e "$RESET"
    echo ""

INSTALL_DIR=/usr/share/scout

echo -e "{$OKBLUE}[This script will uninstall scout and remove ALL files under $INSTALL_DIR. Are you sure you want to continue?$RESET"
read -p "{$OKBLUE}(Y/N): " answer

if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    sudo rm -Rf /usr/share/scout/
    #sudo rm -f /usr/bin/scout
    echo -e "{$OKBOLD$OKGREEN}[ Removed ]$RESET"
else 
    echo -e "{$OKBOLD$OKRED}[ Not Removed ]$RESET"
fi