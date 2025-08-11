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
sleep 0.5

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

#Cloning Project From Github
echo -e "${OKBOLD}${OKBLUE} 1. Cloning Project From Github ${RESET}"
git clone https://github.com/ghost11411/scout -q "$INSTALL_DIR"

#Creating Directories
echo -e "${OKBOLD}${OKBLUE} 2. Making Folders ${RESET}"
mkdir -p "$BIN_DIR" "$WORDLISTS_DIR"
mkdir -p ~/.gf
sleep 1

#Installing Tools
echo -e "${OKBOLD}${OKBLUE} 3. Installing Tools & Dependencies${RESET}"
apt install -y whois jq unzip massdns sqlmap python3 python3-pip python3-argparse python3-requests python3-dnsython git golang-go gobuster parallel &> /dev/null
wget -q -O - https://git.io/vQhTU | bash &>/dev/null
sleep 1
echo -e "${OKBLUE}  Installing mapcidr" && go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest &> /dev/null
echo -e "${OKBLUE}  Installing assetfinder" && go install github.com/tomnomnom/assetfinder@latest &> /dev/null
echo -e "${OKBLUE}  Installing subfinder" && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &> /dev/null
echo -e "${OKBLUE}  Installing waybackurls" && go install github.com/tomnomnom/waybackurls@latest &> /dev/null
echo -e "${OKBLUE}  Installing amass" && go install github.com/owasp-amass/amass/v4/...@master &> /dev/null
echo -e "${OKBLUE}  Installing dnsx" && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest &> /dev/null
echo -e "${OKBLUE}  Installing gf" && go install github.com/tomnomnom/gf@latest &> /dev/null
echo -e "${OKBLUE}  Installing gau" && go install github.com/lc/gau/v2/cmd/gau@latest &> /dev/null
echo -e "${OKBLUE}  Installing gauplus" && go install github.com/bp0lr/gauplus@latest &> /dev/null
echo -e "${OKBLUE}  Installing unfurl" && go install github.com/tomnomnom/unfurl@latest &> /dev/null
echo -e "${OKBLUE}  Installing shuffledns" && go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest &> /dev/null
echo -e "${OKBLUE}  Installing puredns" && go install github.com/d3mondev/puredns/v2@latest &> /dev/null
echo -e "${OKBLUE}  Installing httprobe" && go install github.com/tomnomnom/httprobe@latest &> /dev/null
echo -e "${OKBLUE}  Installing httpx" && go install github.com/projectdiscovery/httpx/cmd/httpx@latest &> /dev/null
echo -e "${OKBLUE}  Installing ffuf" && go install github.com/ffuf/ffuf/v2@latest &> /dev/null
echo -e "${OKBLUE}  Installing subjs" && go install github.com/lc/subjs@latest &> /dev/null
echo -e "${OKBLUE}  Installing nuclei" && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest &> /dev/null
echo -e "${OKBLUE}  Installing subjack" && go install github.com/haccer/subjack@latest &> /dev/null
echo -e "${OKBLUE}  Installing naabu" && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest &> /dev/null
echo -e "${OKBLUE}  Installing kxss" && go install github.com/Emoe/kxss@latest &> /dev/null
echo -e "${OKBLUE}  Installing notify" && go install -v github.com/projectdiscovery/notify/cmd/notify@latest &> /dev/null
echo -e "${OKBLUE}  Installing dalfox" && go install github.com/hahwul/dalfox/v2@latest &> /dev/null
echo -e "${OKBLUE}  Installing Arjun" && pipx install arjun &> /dev/null
echo -e "${OKBLUE}  Installing findomain"
FINDD_VER=$(curl -sL https://api.github.com/repos/Findomain/Findomain/releases/latest | jq -r ".tag_name")
wget "https://github.com/Findomain/Findomain/releases/download/$FINDD_VER/findomain-linux.zip" -O /tmp/findomain.zip &> /dev/null
unzip /tmp/findomain.zip -d $BIN_DIR &> /dev/null
echo -e "${OKBLUE}  Installing sublister"
git clone https://github.com/aboul3la/Sublist3r.git $BIN_DIR/sublister &> /dev/null &> /dev/null
echo -e "${OKBLUE}  Installing sqlmap"
git clone https://github.com/sqlmapproject/sqlmap.git $BIN_DIR/sqlmap &> /dev/null 
mv ~/go/bin/* ${BIN_DIR}
echo -e "${OKBOLD}${OKGREEN} **All Tools Installed** ${RESET}"
echo -e "${OKBLUE} Getting GF Patterns"
# cp -r ~/go/src/github.com/tomnomnom/gf/examples ~/.gf
git clone https://github.com/1ndianl33t/GF-Patterns ~/.gf &> /dev/null
echo -e "${OKBLUE} Updating Nuclie Templates"
nuclei -update-templates &> /dev/null
echo -e
echo -e "${OKBOLD}${OKBLUE} Getting Wordlists ${RESET}"
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O $WORDLISTS_DIR/subdomains.txt &> /dev/null
wget -q https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O $WORDLISTS_DIR/resolvers.txt &> /dev/null
wget -q https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt -O $WORDLISTS_DIR/fuzz.txt &> /dev/null
wget -q https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/dns-Jhaddix.txt -O $WORDLISTS_DIR/dns.txt &> /dev/null
wget -q https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/big.txt -O $WORDLISTS_DIR/big.txt &> /dev/null
wget -q https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt -O "$WORDLISTS_DIR" &>/dev/null
wget -q https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O "$WORDLISTS_DIR" &>/dev/null
wget -q https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O "$WORDLISTS_DIR" &>/dev/null
echo -e
chmod 777 $BIN_DIR/*
echo -e "${OKBOLD}${OKGREEN} **Installation Completed** ${RESET}"
