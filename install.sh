#!/bin/bash
#VARS
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

#TOOLS
AMASS_BIN="$BIN_DIR"/amass
SUBFINDER_BIN="$BIN_DIR"/subfinder
ASSETFINDER_BIN="$BIN_DIR"/assetfinder
FINDOMAIN_BIN="$BIN_DIR"/findomain
FUFF_BIN="$BIN_DIR"/fuff
WAFW00F_BIN="$BIN_DIR"/wafw00f
CTFR_BIN="$BIN_DIR"/ctfr/ctfr.py
ANEW_BIN="$BIN_DIR"/anew
HTTPROBE_BIN="$BIN_DIR"/httprobe
SHUFFLEDNS_BIN="$BIN_DIR"/shuffledns

#URLS
#SUBDOMAINS
AMASS=https://api.github.com/repos/OWASP/Amass/releases/latest
SUBFINDER=https://api.github.com/repos/projectdiscovery/subfinder/releases/latest
ASSETFINDER=https://api.github.com/repos/tomnomnom/assetfinder/releases
FINDDOMAIN=https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip

#DNSENUM
SHUFFLEDNS=https://api.github.com/repos/projectdiscovery/shuffledns/releases/latest

#PROBE
HTTPROBE=https://api.github.com/repos/tomnomnom/httprobe/releases

#FILE SORTING
ANEW=https://api.github.com/repos/tomnomnom/anew/releases

#WEB REQUESTS
FFUF=https://api.github.com/repos/ffuf/ffuf/releases

#Firewall Check
WAFW00F=https://api.github.com/repos/EnableSecurity/wafw00f/releases/latest
GAU=https://api.github.com/repos/lc/gau/releases/latest
# WAYBACKURL=https://api.github.com/repos/tomnomnom/waybackurls/releases/latest

#TOOLS INSTALLATION
function make_bin_folder {
    echo "$OKBLOD$OKBLUE Making Bin Folder$RESET"
    mkdir -p "$BIN_DIR" && chmod 777 -Rf "$BIN_DIR"
}

#MAKE TEMP FOLDER
function make_temp {
    echo "$OKBLOD$OKBLUE Creating Temp Folder $RESET"
    if [ ! -d "$TEMP_DIR" ]; then
        mkdir "$TEMP_DIR" && chmod 777 -Rf "$TEMP_DIR"
    else
        rm -r "$TEMP_DIR" && mkdir "$TEMP_DIR" && chmod 777 -Rf "$TEMP_DIR"
    fi
}

function make_wordlists {
    echo "$OKBLOD$OKBLUE Creating Wordlists Folder $RESET"
    if [ ! -d "$WORDLISTS_DIR" ]; then
        mkdir "$WORDLISTS_DIR"
    else
        rm -r "$WORDLISTS_DIR" && mkdir "$WORDLISTS_DIR"
    fi 
    echo
}

#DOWNLOAD AND INSTALL TOOLS
function install_amass {
    echo  "#### Installing Amass ####"
    if [ ! -f "$AMASS_BIN" ]; then
        amass_ver=$(curl -sL "$AMASS" | jq -r ".tag_name")
        echo "$amass_ver"
        amassf=$(curl -sL "$AMASS" | grep linux_amd64.zip | tail -1 | cut -d '"' -f 4)
        wget "$amassf" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/amass*.zip "$TEMP_DIR"/amass.zip
        unzip "$TEMP_DIR/amass.zip" -d "$TEMP_DIR" >/dev/null
        cp "$TEMP_DIR"/amass_linux_amd64/amass "$BIN_DIR"
        echo "Amass Installed"
    else 
        echo "Already Exists"
    fi
    echo
}

#INSTALL SUBFINDER
function install_subfinder {
    echo "#### Installing Subfinder ####"
    if [ ! -f "$SUBFINDER_BIN" ]; then
        subf_ver=$(curl -sL "$SUBFINDER" | jq -r ".tag_name")
        echo "$subf_ver"
        subf=$(curl -sL "$SUBFINDER" | grep linux_amd64.zip | tail -1 | cut -d '"' -f 4)
	    wget "$subf" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/subfinder*.zip "$TEMP_DIR"/subfinder.zip
        unzip "$TEMP_DIR/subfinder.zip" -d "$BIN_DIR" >/dev/null
        echo "Subfinder Installed"
    else 
        echo "Already Exists"
    fi
    echo
}

#INSTALL ASSETFINDER
function install_assetfinder {
    echo "#### Installing Assetfinder ####"
    if [ ! -f "$ASSETFINDER" ]; then
        assf_ver=$(curl -sL "$ASSETFINDER" | grep tag_name | head -n 1 | cut -d '"' -f 4)
        echo "$assf_ver"
        assf=$(curl -sL "$ASSETFINDER" | grep linux-amd64 | grep browser_download_url | head -n 1 | cut -d '"' -f 4)
	    wget "$assf" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/assetfinder*.tgz "$TEMP_DIR"/assetfinder.tgz
        tar -zxvf "$TEMP_DIR"/assetfinder.tgz -C "$BIN_DIR" >/dev/null
        echo "Assetfinder Installed"
    else 
        echo "Already Exists"
    fi
    echo
}

#INSTALL FINDOMAIN
function install_findomain {
    echo "#### Installing Findomain ####"
    if [ ! -f "$FINDDOMAIN" ]; then
        finddomain_ver=$(curl -sL https://github.com/Findomain/Findomain/releases/latest | grep Findomain | head -n 1 | cut -d "v" -f 2 | cut -d " " -f 1)
        echo "v$finddomain_ver"
        wget "$FINDDOMAIN" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/findomain*.zip "$TEMP_DIR"/findomain.zip
        unzip "$TEMP_DIR"/findomain.zip -d "$TEMP_DIR" >/dev/null && cp -r "$TEMP_DIR"/findomain "$BIN_DIR"
        sudo chmod 777 "$FINDOMAIN_BIN"
        echo "Findomain Installed"
    else
        echo "Already Exists"
    fi
    echo
}

#INSTALL HTTPROBE
function install_httprobe {
    echo "#### Installing Httprobe ####"
    if [ ! -f "$HTTPROBE_BIN" ]; then
        httprobe_ver=$(curl -sL "$HTTPROBE" | jq -r | grep tag_name | head -1 | cut -d '"' -f 4)
        echo "$httprobe_ver"
        httprobe=$(curl -sL "$HTTPROBE" | grep download_url | grep linux-amd64 | head -1 | cut -d '"' -f 4)
	    wget "$httprobe" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/httprobe*.tgz "$TEMP_DIR"/httprobe.tgz
        tar -xvf "$TEMP_DIR"/httprobe.tgz -C "$BIN_DIR" >/dev/null
        echo "Httprobe Installed"
    else 
        echo "Already Exists"
    fi
    echo
}

#INSTALL ANEW
function install_anew {
    echo "#### Installing Anew ####"
    if [ ! -f "$ANEW_BIN" ]; then
        anew_ver=$(curl -sL "$ANEW" | grep tag_name | head -n 1 | cut -d '"' -f 4)
        echo "$anew_ver"
        anew=$(curl -sL "$ANEW" | grep linux-amd64 | grep browser_download_url | head -n 1 | cut -d '"' -f 4)
	    wget "$anew" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/anew*.tgz "$TEMP_DIR"/anew.tgz
        tar -zxvf "$TEMP_DIR"/anew.tgz -C "$BIN_DIR" >/dev/null
        echo "Anew Installed"
    else 
        echo "Already Exists"
    fi
    echo
}

#INSTALL FUFF
function install_ffuf {
    echo "#### Installing FFUF ####"
    if [ ! -f "$FUFF_BIN" ]; then
        ffuf_ver=$(curl -sL "$FFUF" | grep tag_name | head -1 | cut -d '"' -f 4)
        echo "$ffuf_ver"
        ffuf=$(curl -sL "$FFUF" | grep browser_download_url | grep linux_amd64 | head -1 | cut -d '"' -f 4)
        wget "$ffuf" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/ffuf*.tar.gz "$TEMP_DIR"/ffuf.tar.gz
        tar -xvf "$TEMP_DIR"/ffuf.tar.gz -C "$TEMP_DIR" >/dev/null && cp -r "$TEMP_DIR"/ffuf "$BIN_DIR" >/dev/null
        echo "FFUF Installed"
    else 
        echo "Already Exists"
    fi
    echo
}

#INSTALL SHUFFLEDNS
function install_shuffledns {
    echo  "#### Installing ShuffleDNS ####"
    if [ ! -f "$SHUFFLEDNS_BIN" ]; then
        shuffledns_ver=$(curl -sL "$SHUFFLEDNS" | jq -r ".tag_name")
        echo "$shuffledns_ver"
        shufflednsf=$(curl -sL "$SHUFFLEDNS" | grep linux_amd64.zip | tail -1 | cut -d '"' -f 4)
        wget "$shufflednsf" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/shuffledns*.zip "$TEMP_DIR"/shuffledns.zip
        unzip "$TEMP_DIR/shuffledns*.zip" -d "$TEMP_DIR" >/dev/null
        cp "$TEMP_DIR"/shuffledns "$BIN_DIR"
        echo "Shuffledns Installed"
    else 
        echo "Already Exists"
    fi
    echo
}

#INSTALL CTFR
function install_ctfr {
    echo "#### Installing CTFR ####"
    if [ ! -f "$CTFR_BIN" ]; then
        git clone https://github.com/UnaPibaGeek/ctfr.git -q "$BIN_DIR"/ctfr
        pip3 install -r $BIN_DIR/ctfr/requirements.txt
    else
        echo "Already Exists"
    fi
    echo
}

#INSTALL GAU
function install_gau {
    echo "#### Installing GAU ####"
    if [ ! -f "$GAU" ]; then
        gau_ver=$(curl -sL "$GAU" | grep tag_name | head -n 1 | cut -d '"' -f 4)
        echo "$gau_ver"
        gauf=$(curl -sL "$GAU" | grep linux_amd64 | grep browser_download_url | head -n 1 | cut -d '"' -f 4)
	    wget "$gauf" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/gau*.tar.gz "$TEMP_DIR"/gau.tar.gz
        tar -zxvf "$TEMP_DIR"/gau.tar.gz -C "$TEMP_DIR" >/dev/null && cp "$TEMP_DIR"/gau "$BIN_DIR"
        echo "GAU Installed"
    else 
        echo "Already Exists"
    fi
    echo
}

#INSTALL WAFWOOF
function install_wafw00f {
    echo "#### Installing Wafw00f ####"
    if [ ! -f "$WAFW00F_BIN" ]; then
        wafw00f_ver=$(curl -sL "$WAFW00F" | grep tag_name | cut -d '"' -f 4)
        echo "$wafw00f_ver"
        wafw00ff=$(curl -sL "$WAFW00F" | grep zip | cut -d '"' -f 4)
        wget "$wafw00ff" -P "$TEMP_DIR" 2>/dev/null
        mv "$TEMP_DIR"/v* "$TEMP_DIR"/wafw00f.zip
        unzip "$TEMP_DIR"/wafw00f.zip -d "$TEMP_DIR" >/dev/null && mv "$TEMP_DIR"/EnableSecurity*/wafw00f/bin/wafw00f "$BIN_DIR"
        echo "WAFW00F Installed"
    else 
        echo "Already Exists"
    fi
    echo
}   

#Install Wordlists
function install_rockyou {
    echo "#### Installing Rockyou ####"
    if [ ! -f "$WORDLISTS_DIR"/rockyou.txt ]; then
        wget https://raw.githubusercontent.com/zacheller/rockyou/master/rockyou.txt.tar.gz -P "$TEMP_DIR" 2>/dev/null
        sudo tar -xvf "$TEMP_DIR"/rockyou.txt.tar.gz -C "$TEMP_DIR" >/dev/null && cp -r "$TEMP_DIR"/rockyou.txt "$WORDLISTS_DIR"
        echo "Rockyou Installed"
    else
        echo "Already Exists"
    fi
    echo
}

function install_2msubdomain {
    echo "#### Subdomain-Wordlist ####"
    if [ ! -f "$WORDLISTS_DIR"/2m-subdomains.txt ]; then
        wget https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt -P "$WORDLISTS_DIR" 2>/dev/null
        echo "2mSubdomain-Wordlist Installed"
    else
        echo "Already Exists"
    fi
    echo
}

function install_best_dns_wordlist {
    echo "#### Best-DNS-Wordlist ####"
    if [ ! -f "$WORDLISTS_DIR"/best-dns-wordlist.txt ]; then
        wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -P "$WORDLISTS_DIR" 2>/dev/null
        echo "2mSubdomain-Wordlist Installed"
    else
        echo "Already Exists"
    fi
    echo
}

function install_all_txt {
    echo "#### JH-All.txt-Wordlist ####"
    if [ ! -f "$WORDLISTS_DIR"/all.txt ]; then
        wget https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -P "$WORDLISTS_DIR" 2>/dev/null
        echo "JH-All.txt-Wordlist"
    else
        echo "Already Exists"
    fi
    echo
}

function install_seclists {
    echo "#### Seclists-Wordlist ####"
    if [ ! -d "$WORDLISTS_DIR"/SecLists ]; then
        wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -P "$TEMP_DIR" 2>/dev/null
        unzip "$TEMP_DIR"/master.zip -d "$TEMP_DIR" >/dev/null && mv "$TEMP_DIR"/SecLists-master "$WORDLISTS_DIR"/seclists 2>/dev/null
        echo "SecLists Installed"
    else
        echo "Already Exists"
    fi
    echo
}

function install_tools {
    make_bin_folder
    make_temp
    make_wordlists
    apt install -y jq unzip whois
    install_amass
    install_anew
    install_assetfinder
    install_findomain
    install_httprobe
    install_subfinder
    install_shuffledns
    install_ctfr
    install_ffuf
    install_wafw00f
    install_gau
    install_rockyou
    install_2msubdomain
    install_best_dns_wordlist
    install_all_txt
    #install_seclists
    rm -r "$TEMP_DIR"
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
        else 
            echo -e "$OKBOLD$OKRED[Installation Folder Already Exists]$RESET"
            echo -e "$OKBOLD$OKRED[If you want to reinstall, run the script again and select option 2]$RESET"
        fi
        echo;;
    
    2)  echo "$OKBOLD$OKBLUE#Complete Reinstalling Scout#$RESET"
        echo
        echo -e "$OKBOLD$OKBLUE[Removing Scout Folder]"
        rm -r "$INSTALL_DIR" && mkdir -p "$INSTALL_DIR" && chmod 777 -Rf "$INSTALL_DIR"
        echo -e "[Downloading Latest Files]$RESET"
        git clone https://github.com/ghost11411/scout -q "$INSTALL_DIR"
        install_tools
        echo;;
    
    *)  echo "Invalid Input"
        ;;
esac