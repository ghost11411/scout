#!/bin/bash
#COLORS
RESET="\e[0m"
OKBOLD="\033[01;01m"
OKRED="\033[0;31m"
OKGREEN="\033[0;32m"
OKBLUE="\033[1;34m"

#Basic Checks
echo -e 
echo -e "${OKBOLD}${OKBLUE} [*] Running Script ${RESET}"
echo 
sleep 2

#CHECK ROOT
echo -e "${OKBLUE} Checking Root Permissions ${RESET}"
sleep 2
if [ "$EUID" -ne 0 ];then 
    echo -e "${OKRED} !!Please run as root (use sudo ./install.sh)!! ${RESET}"
exit
else
    echo -e "${OKGREEN} **Root Permission Granted** ${RESET}"
fi
echo

#CHECK INTERNET
echo -e "${OKBLUE} Checking Internet Connection ${RESET}"
wget -q --spider http://google.com
if [ $? -eq 0 ]; then
    echo -e " ${OKGREEN} **Online** ${RESET}"
else
    echo -e "${OKRED} !!Offline!! ${RESET}"
    echo -e "${OKRED} !!Connect to Internet and rerun the script!! ${RESET}"
    exit
fi
sleep 2
clear

#DIRECTORIES
INSTALL_DIR=~/scout
TOOLS_DIR="$INSTALL_DIR"/tools
BIN_DIR="$TOOLS_DIR"/bin
WORDLISTS_DIR="$TOOLS_DIR"/wordlists/

# function install_2msubdomain {
#     echo "#### Subdomain-Wordlist ####"
#     wget "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt" -P "$WORDLISTS_DIR" 2>/dev/null && chmod 777 "$WORDLISTS_DIR"/rockyou.txt
#     echo "2mSubdomain-Wordlist Installed"
#     echo
# }

# function install_best_dns_wordlist {
#     echo "#### Best-DNS-Wordlist ####"
#     wget "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" -P "$WORDLISTS_DIR" 2>/dev/null && chmod 777 "$WORDLISTS_DIR"/rockyou.txt
#     echo "2mSubdomain-Wordlist Installed"
#     echo
# }

# function install_all_txt {
#     echo "#### JH-All.txt-Wordlist ####"
#     wget "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt" -P "$WORDLISTS_DIR" 2>/dev/null && chmod 777 "$WORDLISTS_DIR"/rockyou.txt
#     echo "JH-All.txt Wordlist Installed"
#     echo
# }

#DOWNLOAD AND INSTALL TOOLS
function install_tools {
    echo -e "${OKBOLD}${OKBLUE} Making Folders ${RESET}"
    mkdir -p "$BIN_DIR" && chmod 777 -Rf "$BIN_DIR"
    mkdir -p ~/.gf
    mkdir -p "$WORDLISTS_DIR"
    sleep 2
    echo -e "${OKBOLD}${OKBLUE} Installing Tools ${RESET}"
    apt install -y whois jq unzip massdns sqlmap python3 python3-pip git golang-go gobuster parallel &> /dev/null
    sleep 2s
    echo -e "${OKBLUE}  Installing mapcidr" && go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest &> /dev/null
    echo -e "${OKBLUE}  Installing assetfinder" && go install github.com/tomnomnom/assetfinder@latest &> /dev/null
    echo -e "${OKBLUE}  Installing subfinder" && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &> /dev/null
    echo -e "${OKBLUE}  Installing waybackurls" && go install github.com/tomnomnom/waybackurls@latest &> /dev/null
    echo -e "${OKBLUE}  Installing amass" && go install github.com/owasp-amass/amass/v4/...@master &> /dev/null
    echo -e "${OKBLUE}  Installing dnsx" && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest &> /dev/null
    echo -e "${OKBLUE}  Installing gf" && go install github.com/tomnomnom/gf@latest &> /dev/null
    echo -e "${OKBLUE}  Installing gauplus" && go install github.com/bp0lr/gauplus@latest &> /dev/null
    echo -e "${OKBLUE}  Installing unfurl" && go install github.com/tomnomnom/unfurl@latest &> /dev/null
    echo -e "${OKBLUE}  Installing shuffledns" && go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest &> /dev/null
    echo -e "${OKBLUE}  Installing puredns" && go install github.com/d3mondev/puredns/v2@latest &> /dev/null
    echo -e "${OKBLUE}  Installing httprobe" && go install github.com/tomnomnom/httprobe@latest &> /dev/null
    echo -e "${OKBLUE}  Installing httpx" && go install github.com/projectdiscovery/httpx/cmd/httpx@latest &> /dev/null
    echo -e "${OKBLUE}  Installing ffuf" && go install github.com/ffuf/ffuf/v2@latest &> /dev/null
    echo -e "${OKBLUE}  Installing subjs" && go install github.com/lc/subjs@latest &> /dev/null
    echo -e "${OKBLUE}  Installing nuclei" && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest &> /dev/null
    echo -e "${OKBLUE}  Installing subjack" && go install github.com/haccer/subjack &> /dev/null
    echo -e "${OKBLUE}  Installing naabu" && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest &> /dev/null
    echo -e "${OKBLUE}  Installing kxss" && go install github.com/Emoe/kxss@latest &> /dev/null
    echo -e "${OKBLUE}  Installing notify" && go install -v github.com/projectdiscovery/notify/cmd/notify@latest &> /dev/null
    echo -e "${OKBLUE}  Installing dalfox" && go install github.com/hahwul/dalfox/v2@latest &> /dev/null
    echo -e "${OKBLUE}  Installing findomain"
    FINDD_VER=$(curl -sL https://api.github.com/repos/Findomain/Findomain/releases/latest | jq -r ".tag_name")
    wget "https://github.com/Findomain/Findomain/releases/download/$FINDD_VER/findomain-linux.zip" -O /tmp/findomain.zip &> /dev/null
    sudo unzip /tmp/findomain.zip -d $BIN_DIR &> /dev/null
    echo -e "${OKBLUE}  Installing sublister"
    git clone https://github.com/aboul3la/Sublist3r.git $BIN_DIR/sublister &> /dev/null && pip3 install -r $BIN_DIR/sublister/requirements.txt --break-system-packages &> /dev/null
    echo -e "${OKBLUE}  Installing sqlmap"
    git clone https://github.com/sqlmapproject/sqlmap.git $BIN_DIR/sqlmap &> /dev/null 
    mv ~/go/bin/* ${BIN_DIR}
    echo -e "${OKBLUE} Getting GF Patterns"
    # cp -r ~/go/src/github.com/tomnomnom/gf/examples ~/.gf
    git clone https://github.com/1ndianl33t/GF-Patterns ~/.gf &> /dev/null
    echo -e "${OKBLUE} Updating Nuclie Templates"
    nuclei -update-templates &> /dev/null
    echo -e "${OKBOLD}${OKGREEN} All Tools Installed ${RESET}"
    echo -e
    echo -e "${OKBOLD}${OKBLUE} Getting Wordlists ${RESET}"
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O $WORDLISTS_DIR/subdomains.txt &> /dev/null
    wget -q https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O $WORDLISTS_DIR/resolvers.txt &> /dev/null
    wget -q https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt -O $WORDLISTS_DIR/fuzz.txt &> /dev/null
    wget -q https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/dns-Jhaddix.txt -O $WORDLISTS_DIR/dns.txt &> /dev/null
    wget -q https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/big.txt -O $WORDLISTS_DIR/big.txt &> /dev/null
    echo -e
    chmod 777 $BIN_DIR/*
}

echo -e "${OKBOLD}${OKGREEN} Scout will be Installed in "$HOME/scout/" ${RESET}"
echo -e "${OKBLUE} [*] Select Input to Proceed"
echo -e "${OKBLUE}  1. Install Scout"
echo -e "${OKBLUE}  2. Complete Reinstall"
# echo -e "${OKBLUE}  3. Complete Reinstall (Backup Workplace Folder)"
echo -e ""
read -p "Selection: "
echo -e "${RESET}"

case "${REPLY}" in
    
    1)  echo -e "${OKBOLD}${OKBLUE}## Installing Scout ## ${RESET}"
        echo
        if [ ! -d "$INSTALL_DIR" ]; then
            mkdir -p "$INSTALL_DIR" && chmod 777 -Rf "$INSTALL_DIR"
            git clone https://github.com/ghost11411/scout.git -q "$INSTALL_DIR"
            install_tools
            chmod 777 "$INSTALL_DIR"/*
            echo -e "${OKBOLD}${OKBLUE}## Installation Completed ## ${RESET}"
        else 
            echo -e "{$OKBOLD}${OKRED}[Installation Folder Already Exists] ${RESET}"
            echo -e "{$OKBOLD}${OKRED}[If you want to reinstall, rerun the script again and select option 2 or 3] ${RESET}"
        fi
        echo;;
    
    2)  echo -e "${OKBOLD}${OKBLUE}## Complete Reinstalling Scout ## ${RESET}"
        echo
        echo -e "${OKBOLD}${OKBLUE}[Removing Scout Folder]${RESET}"
        rm -r "$INSTALL_DIR" && mkdir -p "$INSTALL_DIR" && chmod 777 -Rf "$INSTALL_DIR" &>/dev/null
        echo -e "${OKBOLD}${OKBLUE}[Downloading Latest Files]${RESET}"
        git clone https://github.com/ghost11411/scout -q "$INSTALL_DIR"
        install_tools
        chmod 777 "$INSTALL_DIR"/* 
        echo -e "${OKBOLD}${OKBLUE}## Installation Completed ## ${RESET}" ;;
    
    # 3)  echo -e "${OKBOLD}${OKBLUE}##Complete Reinstalling Scout (Backup Workspace Folder)## ${RESET}"
    #     echo -e "${OKBOLD}${OKBLUE}[Making Backup]"
    #     cp $WORKSPACE_DIR ~/
    #     echo -e "${OKBOLD}${OKBLUE}[Removing Scout Folder]"
    #     rm -r "$INSTALL_DIR" && mkdir -p "$INSTALL_DIR" && chmod 777 -Rf "$INSTALL_DIR"
    #     echo -e "[Downloading Latest Files]${RESET}"
    #     git clone https://github.com/ghost11411/scout -q "$INSTALL_DIR"
    #     install_tools
    #     cp /tmp/ $WORKSPACE_DIR
    #     chmod 777 "$INSTALL_DIR"/* ;;
    
    *)  echo "Invalid Input"
        ;;
esac
