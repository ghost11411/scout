#!/bin/bash
#COLORS
RESET=$(tput sgr0)
OKBOLD=$(tput bold)
OKRED=$(tput setaf 1)
OKGREEN=$(tput setaf 2)
OKBLUE=$(tput setaf 4)

#DIRECTORIES
INSTALL_DIR=/usr/share/scout
TEMP_DIR="$INSTALL_DIR"/tmp
TOOLS_DIR="$INSTALL_DIR"/tools
BIN_DIR="$TOOLS_DIR"/bin
WORDLISTS_DIR="$TOOLS_DIR"/wordlists/
WORKSPACE_DIR="$INSTALL_DIR"/workspace

#TOOLS INSTALLATION
function make_bin_folder {
    echo "$OKBLOD$OKBLUE Making Bin Folder$RESET"
    mkdir -p "$BIN_DIR" && chmod 777 -Rf "$BIN_DIR"
}

#MAKE TEMP FOLDER
function make_temp {
    echo "$OKBLOD$OKBLUE Creating Temp Folder $RESET"
    mkdir "$TEMP_DIR" && chmod 777 -Rf "$TEMP_DIR"
}

#MAKE WORDLISTS FOLDER
function make_wordlists {
    echo "$OKBLOD$OKBLUE Creating Wordlists Folder $RESET"
    mkdir "$WORDLISTS_DIR"
    echo
}

##DOWNLOAD AND INSTALL TOOLS
#INSTALL MAPCIDR
function install_mapcidr {
    echo  "#### Installing MapCIDR ####"
    MAPCIDR_VER=$(curl -sL "https://api.github.com/repos/projectdiscovery/mapcidr/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "$MAPCIDR_VER"
    wget "https://github.com/projectdiscovery/mapcidr/releases/download/v${MAPCIDR_VER}/mapcidr_${MAPCIDR_VER}_linux_amd64.zip" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/mapcidr*.zip "$TEMP_DIR"/mapcidr.zip
    unzip "$TEMP_DIR/mapcidr.zip" -d "$TEMP_DIR" >/dev/null
    cp "$TEMP_DIR"/mapcidr "$BIN_DIR"
    rm -rf $TEMP_DIR/*
    echo "MapCIDR Installed"
    echo
}

#INSTALL DNSX
function install_dnsx {
    echo  "#### Installing Dnsx ####"
    DNSX_VER=$(curl -sL "https://api.github.com/repos/projectdiscovery/dnsx/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "$DNSX_VER"
    wget "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VER}/dnsx_${DNSX_VER}_linux_amd64.zip" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/dnsx*.zip "$TEMP_DIR"/dnsx.zip
    unzip "$TEMP_DIR/dnsx.zip" -d "$TEMP_DIR" >/dev/null
    cp "$TEMP_DIR"/dnsx "$BIN_DIR"
    rm -rf $TEMP_DIR/*rm -rf $TEMP_DIR/*
    echo "DnsX Installed"
    echo
}

#INSTALL AMASS
function install_amass {
    echo  "#### Installing Amass ####"
    AMASS_VER=$(curl -sL "https://api.github.com/repos/OWASP/Amass/releases/latest" | jq -r ".tag_name")
    echo "$AMASS_VER"
    wget "https://github.com/owasp-amass/amass/releases/download/$AMASS_VER/amass_Linux_amd64.zip" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/amass*.zip "$TEMP_DIR"/amass.zip
    unzip "$TEMP_DIR/amass.zip" -d "$TEMP_DIR" >/dev/null
    cp "$TEMP_DIR"/amass_Linux_amd64/amass "$BIN_DIR"
    rm -rf $TEMP_DIR/*
    echo "Amass Installed"
    echo
}

#INSTALL SUBFINDER
function install_subfinder {
    echo "#### Installing Subfinder ####"
    SUBF_VER=$(curl -sL "https://api.github.com/repos/projectdiscovery/subfinder/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "v$SUBF_VER"
    wget "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBF_VER}/subfinder_${SUBF_VER}_linux_amd64.zip" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/subfinder*.zip "$TEMP_DIR"/subfinder.zip
    unzip "$TEMP_DIR/subfinder.zip" -d "$BIN_DIR" >/dev/null
    rm -rf $TEMP_DIR/*
    echo "Subfinder Installed"
    echo
}

#INSTALL ASSETFINDER
function install_assetfinder {
    echo "#### Installing Assetfinder ####"
    ASSF_VER=$(curl -sL "https://api.github.com/repos/tomnomnom/assetfinder/releases" | grep tag_name | head -n 1 | cut -d '"' -f 4)
    echo "$ASSF_VER"
    wget "https://github.com/tomnomnom/assetfinder/releases/download/$ASSF_VER/assetfinder-linux-amd64-0.1.1.tgz" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/assetfinder*.tgz "$TEMP_DIR"/assetfinder.tgz
    tar -zxvf "$TEMP_DIR"/assetfinder.tgz -C "$BIN_DIR" >/dev/null
    rm -rf $TEMP_DIR/*
    echo "Assetfinder Installed"
    echo
}

#INSTALL FINDOMAIN
function install_findomain {
    echo "#### Installing Findomain ####"
    FINDD_VER=$(curl -sL https://api.github.com/repos/Findomain/Findomain/releases/latest | jq -r ".tag_name")
    echo "v$FINDD_VER"
    wget "https://github.com/Findomain/Findomain/releases/download/$FINDD_VER/findomain-linux.zip" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/findomain*.zip "$TEMP_DIR"/findomain.zip
    unzip "$TEMP_DIR"/findomain.zip -d "$TEMP_DIR" >/dev/null && cp -r "$TEMP_DIR"/findomain "$BIN_DIR"
    sudo chmod 777 "$BIN_DIR"/findomain
    rm -rf $TEMP_DIR/*
    echo "Findomain Installed"
    echo
}

#INSTALL WAYBACKURL
function install_waybackurl {
    echo "#### Installing WayBackUrl ####"
    WBU_VER=$(curl -sL https://api.github.com/repos/tomnomnom/waybackurls/releases/latest | jq -r ".tag_name" | sed s/"v"//)
    echo "v$WBU_VER"
    wget "https://github.com/tomnomnom/waybackurls/releases/download/v${WBU_VER}/waybackurls-linux-amd64-${WBU_VER}.tgz" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/waybackurls*.tgz "$TEMP_DIR"/waybackurls.tgz
    tar -zxvf "$TEMP_DIR"/waybackurls.tgz -C "$BIN_DIR" >/dev/null
    sudo chmod 777 "$BIN_DIR"/waybackurls
    rm -rf $TEMP_DIR/*
    echo "WayBackUrls Installed"
    echo
}

#INSTALL CTFR
function install_ctfr {
    echo "#### Installing CTFR ####"
    git clone https://github.com/UnaPibaGeek/ctfr.git -q "$BIN_DIR"/ctfr &>/dev/null
    pip3 install -r $BIN_DIR/ctfr/requirements.txt &>/dev/null
    rm -rf $TEMP_DIR/*
    echo "CTFR Installed"
    echo
}

#INSTALL ANEW
function install_anew {
    echo "#### Installing Anew ####"
    ANEW_VER=$(curl -sL "https://api.github.com/repos/tomnomnom/anew/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "v$ANEW_VER"
    wget "https://github.com/tomnomnom/anew/releases/download/v$ANEW_VER/anew-linux-amd64-$ANEW_VER.tgz" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/anew*.tgz "$TEMP_DIR"/anew.tgz
    tar -zxvf "$TEMP_DIR"/anew.tgz -C "$BIN_DIR" >/dev/null
    rm -rf $TEMP_DIR/*
    echo "Anew Installed"
    echo
}

#INSTALL SHUFFLEDNS
function install_shuffledns {
    echo  "#### Installing ShuffleDNS ####"
    SHUFDNS_VER=$(curl -sL "https://api.github.com/repos/projectdiscovery/shuffledns/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "v$SHUFDNS_VER"
    wget "https://github.com/projectdiscovery/shuffledns/releases/download/v$SHUFDNS_VER/shuffledns_${SHUFDNS_VER}_linux_amd64.zip" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/shuffledns*.zip "$TEMP_DIR"/shuffledns.zip
    unzip "$TEMP_DIR/shuffledns*.zip" -d "$TEMP_DIR" >/dev/null
    cp "$TEMP_DIR"/shuffledns "$BIN_DIR"
    rm -rf $TEMP_DIR/*
    echo "Shuffledns Installed"
    echo
}

#INSTALL PUREDNS
function install_puredns {
    echo  "#### Installing PureDNS ####"
    PURE_VER=$(curl -sL "https://api.github.com/repos/d3mondev/puredns/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "v$PURE_VER"
    wget "https://github.com/d3mondev/puredns/releases/download/v${PURE_VER}/puredns-Linux-amd64.tgz" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/puredns*.tgz "$TEMP_DIR"/puredns.tgz
    tar -zxvf "$TEMP_DIR"/puredns.tgz -C "$BIN_DIR" >/dev/null
    rm -rf $TEMP_DIR/*
    echo "PureDns Installed"
    echo
}

#INSTALL HTTPROBE
function install_httprobe {
    echo "#### Installing Httprobe ####"
    HTTPROBE_VER=$(curl -sL "https://api.github.com/repos/tomnomnom/httprobe/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "v$HTTPROBE_VER"
    wget "https://github.com/tomnomnom/httprobe/releases/download/v$HTTPROBE_VER/httprobe-linux-amd64-$HTTPROBE_VER.tgz" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/httprobe*.tgz "$TEMP_DIR"/httprobe.tgz
    tar -xvf "$TEMP_DIR"/httprobe.tgz -C "$BIN_DIR" >/dev/null
    rm -rf $TEMP_DIR/*
    echo "Httprobe Installed"
    echo
}

#INSTALL HTTPX
function install_httpx {
    echo  "#### Installing Httpx ####"
    HTTPX_VER=$(curl -sL "https://api.github.com/repos/projectdiscovery/httpx/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "v$HTTPX_VER"
    wget "https://github.com/projectdiscovery/httpx/releases/download/v$HTTPX_VER/httpx_${HTTPX_VER}_linux_arm64.zip" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/httpx*.zip "$TEMP_DIR"/httpx.zip
    unzip "$TEMP_DIR/httpx*.zip" -d "$TEMP_DIR" >/dev/null
    cp "$TEMP_DIR"/httpx "$BIN_DIR"
    rm -rf $TEMP_DIR/*
    echo "Httpx Installed"
    echo
}

#INSTALL FUFF
function install_ffuf {
    echo "#### Installing FFUF ####"
    FFUF_VER=$(curl -sL "https://api.github.com/repos/ffuf/ffuf/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "v$FFUF_VER"
    wget "https://github.com/ffuf/ffuf/releases/download/v$FFUF_VER/ffuf_${FFUF_VER}_linux_amd64.tar.gz" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/ffuf*.tar.gz "$TEMP_DIR"/ffuf.tar.gz
    tar -xvf "$TEMP_DIR"/ffuf.tar.gz -C "$TEMP_DIR" >/dev/null && cp -r "$TEMP_DIR"/ffuf "$BIN_DIR" >/dev/null
    rm -rf $TEMP_DIR/*
    echo "FFUF Installed"
    echo
}

#INSTALL GAU
function install_gau {
    echo "#### Installing GAU ####"
    GAU_VER=$(curl -sL "https://api.github.com/repos/lc/gau/releases/latest" |  jq -r ".tag_name" | sed s/"v"//)
    echo "$GAU_VER"
	wget "https://github.com/lc/gau/releases/download/v${GAU_VER}/gau_${GAU_VER}_linux_amd64.tar.gz" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/gau*.tar.gz "$TEMP_DIR"/gau.tar.gz
    tar -zxvf "$TEMP_DIR"/gau.tar.gz -C "$TEMP_DIR" >/dev/null && cp "$TEMP_DIR"/gau "$BIN_DIR"
    rm -rf $TEMP_DIR/*
    echo "GAU Installed"
    echo
}

#INSTALL UNFURL
function install_unfurl {
    echo "#### Installing UNFURL ####"
    UNFURL_VER=$(curl -sL "https://api.github.com/repos/tomnomnom/unfurl/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "v$UNFURL_VER"
    wget "https://github.com/tomnomnom/unfurl/releases/download/v${UNFURL_VER}/unfurl-linux-amd64-${UNFURL_VER}.tgz" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/unfurl*.tgz "$TEMP_DIR"/unfurl.tgz
    tar -xvf "$TEMP_DIR"/unfurl.tgz -C "$BIN_DIR" >/dev/null
    rm -rf $TEMP_DIR/*
    echo "UNFURL Installed"
    echo
}

#INSTALL SUBJS
function install_subjs {
    echo "#### Installing SUBJS ####"
    SUBJS_VER=$(curl -sL "https://api.github.com/repos/lc/subjs/releases/latest" |  jq -r ".tag_name" | sed s/"v"//)
    echo "$SUBJS_VER"
	wget "https://github.com/lc/subjs/releases/download/v${SUBJS_VER}/subjs_${SUBJS_VER}_linux_amd64.tar.gz" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/subjs*.tar.gz "$TEMP_DIR"/subjs.tar.gz
    tar -zxvf "$TEMP_DIR"/subjs.tar.gz -C "$TEMP_DIR" >/dev/null && cp "$TEMP_DIR"/subjs "$BIN_DIR"
    rm -rf $TEMP_DIR/*
    echo "SUBJS Installed"
    echo
}

#INSTALL WAFWOOF
function install_wafw00f {
    echo "#### Installing Wafw00f ####"
       WAFF_VER=$(curl -sL "https://api.github.com/repos/EnableSecurity/wafw00f/releases/latest" | jq -r ".tag_name" | sed s/"v"//)
    echo "v$WAFF_VER"
    wget "https://github.com/EnableSecurity/wafw00f/archive/refs/tags/v$WAFF_VER.zip" -P "$TEMP_DIR" 2>/dev/null
    mv "$TEMP_DIR"/v* "$TEMP_DIR"/wafw00f.zip
    unzip "$TEMP_DIR"/wafw00f.zip -d "$TEMP_DIR" >/dev/null && mv "$TEMP_DIR"/EnableSecurity*/wafw00f/bin/wafw00f "$BIN_DIR"
    rm -rf $TEMP_DIR/*
    echo "WAFW00F Installed"
    echo
}   

#Install Wordlists
function install_rockyou {
    echo "#### Installing Rockyou ####"
    wget "https://raw.githubusercontent.com/zacheller/rockyou/master/rockyou.txt.tar.gz" -P "$TEMP_DIR" 2>/dev/null
    sudo tar -xvf "$TEMP_DIR"/rockyou.txt.tar.gz -C "$TEMP_DIR" >/dev/null && mv "$TEMP_DIR"/rockyou.txt "$WORDLISTS_DIR" && chmod 777 "$WORDLISTS_DIR"/rockyou.txt
    rm -rf $TEMP_DIR/*
    echo "Rockyou Installed"
    echo
}

function install_2msubdomain {
    echo "#### Subdomain-Wordlist ####"
    wget "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt" -P "$WORDLISTS_DIR" 2>/dev/null && chmod 777 "$WORDLISTS_DIR"/rockyou.txt
    echo "2mSubdomain-Wordlist Installed"
    echo
}

function install_best_dns_wordlist {
    echo "#### Best-DNS-Wordlist ####"
    wget "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" -P "$WORDLISTS_DIR" 2>/dev/null && chmod 777 "$WORDLISTS_DIR"/rockyou.txt
    echo "2mSubdomain-Wordlist Installed"
    echo
}

function install_all_txt {
    echo "#### JH-All.txt-Wordlist ####"
    wget "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt" -P "$WORDLISTS_DIR" 2>/dev/null && chmod 777 "$WORDLISTS_DIR"/rockyou.txt
    echo "JH-All.txt Wordlist Installed"
    echo
}

function install_seclists {
    echo "#### Seclists-Wordlist ####"
    wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -P "$TEMP_DIR" 2>/dev/null
    unzip "$TEMP_DIR"/master.zip -d "$TEMP_DIR" >/dev/null && mv "$TEMP_DIR"/SecLists-master "$WORDLISTS_DIR"/seclists 2>/dev/null && chmod 777 "$WORDLISTS_DIR"/rockyou.txt
    echo "SecLists Installed"
    echo
}

function install_dns-resolver {
    echo "#### Installing Custom-dns-resolvers ####"
    wget "https://raw.githubusercontent.com/ghost11411/dns-resolver-list/main/custom-dns-list.txt" -P "$WORDLISTS_DIR" 2>/dev/null && chmod 777 "$WORDLISTS_DIR"/rockyou.txt
    echo "DNS-Resolver Installed"
    echo
}

function install_tools {
    make_bin_folder
    make_temp
    make_wordlists
    echo "Installing whois jq unzip python3 python3-pip massdns hakrawler gospider"
    apt install -y whois jq unzip python3 python3-pip massdns &>/dev/null
    echo
    install_mapcidr
    install_dnsx
    install_amass
    install_assetfinder
    install_findomain
    install_subfinder
    # install_ctfr
    install_waybackurl
    install_gau
    install_unfurl
    install_anew
    install_shuffledns
    install_puredns
    install_httprobe
    install_httpx
    install_ffuf
    install_subjs
    # install_wafw00f
    # install_rockyou
    # install_2msubdomain
    # install_best_dns_wordlist
    # install_all_txt
    # install_seclists
    # install_dns-resolver
    rm -rf $TEMP_DIR
}

#Banner
echo -e "$OKBOLD$OKRED" 
echo -e "                      _   "
echo -e "                     | |  "
echo -e "  ___  ___ ___  _   _| |_ "
echo -e " / __|/ __/ _ \| | | | __|"
echo -e " \__ \ (_| (_) | |_| | |_ "
echo -e " |___/\___\___/ \__,_|\__|"
echo -e "$RESET"
echo ""
echo -e "$OKBOLD LEGENDS:"
echo -e "$OKBOLD$OKBLUE Blue = Script Running $RESET"
echo -e "$OKBOLD$OKGREEN Green = Everything Fine $RESET"
echo -e "$OKBOLD$OKRED Red = ERROR $RESET"

#Basic Checks
echo -e "$OKBOLD"
echo -e "$OKBLUE [*] Running Script$RESET"
echo 

#CHECK ROOT
echo -e "$OKBLUE Checking Root Permissions$RESET"
if [ "$EUID" -ne 0 ];then 
    echo -e "$OKBOLD$OKRED Please run as root (use sudo ./install.sh)$RESET"
exit
else
    echo -e "$OKBOLD$OKGREEN **Root Permission Granted**$RESET"
fi
echo

#CHECK INTERNET
echo -e "$OKBLUE Checking Internet Connection$RESET"
wget -q --spider http://google.com
if [ $? -eq 0 ]; then
    echo -e "$OKBOLD$OKGREEN **Online** $RESET"
else
    echo -e "$OKBOLD"
    echo -e "$OKRED !!Offline!!"
    echo -e "$OKRED !!Connect to Internet and rerun the script!! $RESET"
    exit
fi
echo

echo -e "$OKBOLD Scout will be Installed in /usr/share/scout/"
echo -e "$OKBLUE [*] Select Input to Proceed$RESET"
echo -e "$OKBLUE  1. Install Scout"
echo -e "$OKBLUE  2. Complete Reinstall"
echo -e "$OKBLUE  3. Complete Reinstall (Backup Workplace Folder)"
echo -e ""
read -p "Selection: "
echo -e "$RESET"

case "${REPLY}" in
    
    1)  echo "$OKBOLD$OKBLUE#Installing Scout#$RESET"
        echo
        if [ ! -d "$INSTALL_DIR" ]; then
            mkdir -p "$INSTALL_DIR" && chmod 777 -Rf "$INSTALL_DIR"
            git clone https://github.com/ghost11411/scout.git -q "$INSTALL_DIR"
            install_tools
            chmod 777 "$INSTALL_DIR"/*
        else 
            echo -e "{$OKBOLD$OKRED}[Installation Folder Already Exists]$RESET"
            echo -e "{$OKBOLD$OKRED}[If you want to reinstall, rerun the script again and select option 2 or 3]$RESET"
        fi
        echo;;
    
    2)  echo "$OKBOLD$OKBLUE#Complete Reinstalling Scout#"
        echo
        echo -e "[Removing Scout Folder]"
        rm -r "$INSTALL_DIR" && mkdir -p "$INSTALL_DIR" && chmod 777 -Rf "$INSTALL_DIR" &>/dev/null
        echo -e "[Downloading Latest Files]$RESET"
        git clone https://github.com/ghost11411/scout -q "$INSTALL_DIR"
        install_tools
        chmod 777 "$INSTALL_DIR"/* ;;
    
    3)  echo "$OKBOLD$OKBLUE#Complete Reinstalling Scout (Backup Workspace Folder)#$RESET"
        echo -e "{$OKBOLD$OKBLUE}[Making Backup]"
        cp $WORKSPACE_DIR ~/
        echo -e "{$OKBOLD$OKBLUE}[Removing Scout Folder]"
        rm -r "$INSTALL_DIR" && mkdir -p "$INSTALL_DIR" && chmod 777 -Rf "$INSTALL_DIR"
        echo -e "[Downloading Latest Files]$RESET"
        git clone https://github.com/ghost11411/scout -q "$INSTALL_DIR"
        install_tools
        cp /tmp/ $WORKSPACE_DIR
        chmod 777 "$INSTALL_DIR"/*;;
    
    *)  echo "Invalid Input"
        ;;
esac