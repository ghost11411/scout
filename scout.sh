#!/bin/bash

#GET TARGET
echo "Enter Company Name: " 
read "TARGET"
echo

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
WORKSPACE_DIR="$INSTALL_DIR"/workspace
TARGET_DIR="$WORKSPACE_DIR"/"$TARGET"
SUBDOMAINS_DIR="$TARGET_DIR"/subdomains
RAW_DIR="$SUBDOMAINS_DIR"/raw
ACTIVE_DIR="$SUBDOMAINS_DIR"/active
FINAL_DIR="$SUBDOMAINS_DIR"/final

#RAW FILES
AMASS_INTEL_OUT="$RAW_DIR"/amass_intel.out
AMASS_ENUM_OUT="$RAW_DIR"/amass_enum.out
SUBFINDER_OUT="$RAW_DIR"/subfinder.out
ASSETFINDER_OUT="$RAW_DIR"/assetfinder.out
FINDDOMAIN_OUT="$RAW_DIR"/findomain.out

#COLLECTED FILES
COLLECTED="$RAW_DIR"/collected.out
COLLECTED_SORTED="$RAW_DIR"/collected.sorted.out

#ACTIVE FILES
DNS_ACTIVE="$ACTIVE_DIR"/dns_active.out
DNS_ACTIVE_SORTED="$ACTIVE_DIR"/dns_active_sorted.out
ACTIVE="$ACTIVE_DIR"/active.out
ACTIVE_SORTED="$ACTIVE_DIR"/active.sorted.out

#TOOLS
AMASS_BIN="$BIN_DIR"/amass
SUBFINDER_BIN="$BIN_DIR"/subfinder
ASSETFINDER_BIN="$BIN_DIR"/assetfinder
FINDOMAIN_BIN="$BIN_DIR"/findomain
HTTPROBE_BIN="$BIN_DIR"/httprobe
ANEW_BIN="$BIN_DIR"/anew
FUFF_BIN="$BIN_DIR"/fuff
WAFW00F_BIN="$BIN_DIR"/wafw00f
SHUFFLEDNS_BIN="$BIN_DIR"/shuffledns

#Basic Checks
echo -e "$OKBOLD"
echo -e "$OKBLUE [*] Running Script$RESET"
echo 

#CHECK ROOT
echo -e "$OKBLUE Checking Root Permissions$RESET"
if [ "$EUID" -ne 0 ];then 
    echo -e "$OKBOLD$OKRED Please run as root (use sudo ./scout.sh)$RESET"
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

if [ ! -d "$INSTALL_DIR" ] && [ $(ls "$BIN_DIR" | wc -l) -eq "0" ]; then
    echo -e "$OKRED[ Run Install script first (sudo ./install.sh)]$RESET"
    exit
else
    echo "Everything is OK"
fi
echo

WILDCARDS=$1
IN_SCOPE=$2
OUT_SCOPE=$3

#CREATE FOLDERS 
if [ ! -d "$TARGET_DIR" ]; then
  echo "#### Creating Target Folders ####"
  sudo mkdir -p "$TARGET_DIR"
  sudo mkdir -p "$SUBDOMAINS_DIR"
  sudo mkdir -p "$RAW_DIR" "$ACTIVE_DIR" "$FINAL_DIR"
else
  echo "Target Folder Already Exist"
fi
echo

while read -r line; do
    res=$(host -t a $line)
    if [ $(echo $res | cut -d ' ' -f 3) == 'no' ]; then
        echo "Not Found $WILDCARDS"
    else
        whois $(echo $res | cut -d ' ' -f 4) | grep "CIDR" | cut -d ':' -f 2 >> $SUBDOMAINS_DIR/ip_block
        sed "s/^[ \t]*//" -i $SUBDOMAINS_DIR/ip_block
        whois $($SUBDOMAINS_DIR/ip_block) | grep "CIDR" >> $SUBDOMAINS_DIR/cidr
    fi
    sleep 2
done < "$WILDCARDS"

while read -r line; do
    cat cidr | mapcidr -silent | dnsx -ptr -resp-only -o test
    sed -i "/\googleuser\b/d" test
done < "$SUBDOMAINS"/cidr

echo "#### Running Amass ####"
# "$AMASS_BIN" intel -whois -df in-scope -o "$AMASS_INTEL_OUT"              # Find Root Domains
"$AMASS_BIN" enum -passive -df $WILDCARDS -timeout 10 -o "$AMASS_ENUM_OUT"      # Find Subdomains
echo

echo "#### Running SubFinder ####"
"$SUBFINDER_BIN" -dL $WILDCARDS -all -t 20 -nW -silent -o "$SUBFINDER_OUT"
echo

echo "#### Running AssetFinder ####"
cat "$WILDCARDS" | "$ASSETFINDER_BIN" -subs-only > "$ASSETFINDER_OUT"
echo "Done"
echo

echo "#### Running FindDomain ####"
"$FINDOMAIN_BIN" --file "$WILDCARDS" -q -u "$FINDDOMAIN_OUT"
echo "Done"
echo

# SORT ALL SUB-DOMAINS
echo "#### Sorting Files ####"
touch "$COLLECTED"
cat "$AMASS_ENUM_OUT" | "$ANEW_BIN" "$COLLECTED"
cat "$SUBFINDER_OUT" | "$ANEW_BIN" "$COLLECTED"
cat "$ASSETFINDER_OUT" | "$ANEW_BIN" "$COLLECTED"
cat "$FINDDOMAIN_OUT" | "$ANEW_BIN" "$COLLECTED"
sort "$COLLECTED" > "$COLLECTED_SORTED"
#grep -F -vf  "$OUT_SCOPE" "$COLLECTED_SORTED" > "$COLLECTED_FINAL"
echo

echo "#### Running ShuffleDNS ####"
if [ -f $COLLECTED_SORTED ]; then
  echo -e "$OKBOLD$OKGREEN Collected File Found $RESET"
  "$SHUFFLEDNS_BIN" -l "$COLLECTED_SORTED" -r $WORDLISTS_DIR/dns-resolvers-custom -o "$DNS_ACTIVE" -silent
  sort "$DNS_ACTIVE" > "$DNS_ACTIVE_SORTED"
  echo "Done"
else
  echo -e "$OKBOLD$OKRED[Collected File Not Found]$RESET"
fi
echo

echo "#### Running HTTProbe ####"
if [ -f "$DNS_ACTIVE_SORTED" ]; then
  echo -e "$OKGREEN DNS Active File Found $RESET"
  touch "$ACTIVE"
  cat "$DNS_ACTIVE_SORTED" | "$HTTPROBE_BIN" -prefer-https > "$ACTIVE"
  sort "$ACTIVE" > "$ACTIVE_SORTED"
  echo "Done"
else
  echo -e "$OKRED DNS Active File Not Found"
fi
echo