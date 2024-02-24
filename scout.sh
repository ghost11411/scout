#!/bin/bash

#  VERSION=1.0

#GET TARGET
echo "Enter Company Name: " 
read -r "TARGET"
echo

#VARS
RESET=$(tput sgr0)
OKBOLD=$(tput bold)
OKRED=$(tput setaf 1)
OKGREEN=$(tput setaf 2)
OKBLUE=$(tput setaf 4)

#DIRECTORIES
INSTALL_DIR=/usr/share/scout
# TEMP_DIR="$INSTALL_DIR"/tmp
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
ASN_OUT="$RAW_DIR"/asn
IPBLOCK_OUT="$RAW_DIR"/ip_block
# AMASS_INTEL_OUT="$RAW_DIR"/amass_intel.out
AMASS_ENUM_OUT="$RAW_DIR"/amass_enum.out
SUBFINDER_OUT="$RAW_DIR"/subfinder.out
ASSETFINDER_OUT="$RAW_DIR"/assetfinder.out
FINDDOMAIN_OUT="$RAW_DIR"/findomain.out
GAU_OUT="$RAW_DIR"/gau
SUBD_GAU_OUT="$RAW_DIR"/subd_gau.out
WAYBACKURL_OUT="$RAW_DIR"/waybackurl
SUBD_WAYBACKURL_OUT="$RAW_DIR"/subd_waybackurl.out
CRT_OUT="$RAW_DIR"/crt.out

#COLLECTED FILES
COLLECTED="$RAW_DIR"/collected
COLLECTED_SORTED="$RAW_DIR"/collected.sorted

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
WAYBACKURL_BIN="$BIN_DIR"/waybackurls
GAU_BIN="$BIN_DIR"/gau
UNFURL_BIN="$BIN_DIR"/unfurl
ANEW_BIN="$BIN_DIR"/anew
HTTPROBE_BIN="$BIN_DIR"/httprobe
HTTPX_BIN="$BIN_DIR"/httpx
SHUFFLEDNS_BIN="$BIN_DIR"/shuffledns
PUREDNS_BIN="$BIN_DIR"/purends
FUFF_BIN="$BIN_DIR"/fuff
SUBJS_BIN="$BIN_DIR"/subjs
# WAFW00F_BIN="$BIN_DIR"/wafw00f

USAGE(){
	while read -r line; do
		printf "%b\n" "$line"
	done <<-EOF
	$OKRED\r
	\r ${OKBOLD}${OKBLUE}Options${RESET}:
	\r    -df         - File of Domains
	\r    -h          - Displays this help message and exit.
	\r    -v          - Displays the version and exit.

	\r${OKBOLD}${OKBLUE}Examples${RESET}: 
	\r    - To run scout.sh against a list of domains:
	\r       ./scout.sh -df domains.txt$RESET
EOF
	exit 1
}

function banner {
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
}

#Basic Checks
function checks {
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

  if [ ! -d "$INSTALL_DIR" ] || [ "$(ls $BIN_DIR | wc -l)" -eq "0" ]; then
    echo -e "${OKRED}[ Run Install script first and select desired option (sudo ./install.sh)]$RESET"
    exit
  else
    echo "$OKBOLD$OKBLUE Everything is OK$RESET"
  fi
  echo
}

#CREATE FOLDERS 
function create_folders {
  if [ ! -d "$TARGET_DIR" ]; then
    echo "$OKBLUE#### Creating Target Folders ####$RESET"
    sudo mkdir -p "$TARGET_DIR"
    sudo mkdir -p "$SUBDOMAINS_DIR"
    sudo mkdir -p "$RAW_DIR" "$ACTIVE_DIR" "$FINAL_DIR"
  else
    echo "$OKBOLD$OKRED Target Folder Already Exist$RESET"
    echo "$OKBOLD$OKRED Recreating Target Folder $RESET"
    sudo rm -Rf "$TARGET_DIR"
    sudo mkdir -p "$TARGET_DIR"
    sudo mkdir -p "$SUBDOMAINS_DIR"
    sudo mkdir -p "$RAW_DIR" "$ACTIVE_DIR" "$FINAL_DIR"
  fi
  echo
}

function get_asn_cidr {
	while read -r line; do
    touch "$ASN_OUT" "$IPBLOCK_OUT"
    res=$(host -t a "$line")
    ip=$(echo "$res" | cut -d " " -f 4)
    whois -h riswhois.ripe.net "$ip" | grep "origin" | tail -n+2 | cut -d ":" -f 2 | sed "s/^[ \t]*//" | "$ANEW_BIN" "$ASN_OUT" &>/dev/null
    whois -h riswhois.ripe.net "$ip" | grep "route" | cut -d ":" -f 2 | sed "s/^[ \t]*//" | "$ANEW_BIN" "$IPBLOCK_OUT" &>/dev/null
	done < "$WILDCARDS"
  echo -e "$OKBOLD$OKGREEN [*] Found ASN$RESET: $(wc -l < "$ASN_OUT")" 
  cat "$ASN_OUT"
  echo
  echo -e "$OKBOLD$OKGREEN [*] Found IP_Block$RESET: $(wc -l < "$IPBLOCK_OUT")"
  cat "$IPBLOCK_OUT"
  echo
}

function run_amass {
  echo "$OKBOLD$OKBLUE#### Running Amass ####$RESET"
  # "$AMASS_BIN" intel -whois -df in-scope -o "$AMASS_INTEL_OUT"                   # Find Root Domains
  "$AMASS_BIN" enum -passive -df "$WILDCARDS" -o "$AMASS_ENUM_OUT" &>/dev/null     # Find Subdomains
  echo -e "$OKBOLD$OKGREEN""[+] Amass Found:$RESET $(wc -l < $AMASS_ENUM_OUT)"
  echo
}

function run_subfinder {
  echo "$OKBOLD$OKBLUE#### Running SubFinder ####$RESET"
  "$SUBFINDER_BIN" -dL "$WILDCARDS" -all -t 100 -silent -o "$SUBFINDER_OUT" &>/dev/null
  echo -e "$OKBOLD$OKGREEN""[+] SubFinder Found:$RESET $(wc -l < $SUBFINDER_BIN)"
  echo
}

function run_assetfinder {
  echo "$OKBOLD$OKBLUE#### Running AssetFinder ####$RESET"
  cat "$WILDCARDS" | "$ASSETFINDER_BIN" -subs-only | $ANEW_BIN "$ASSETFINDER_OUT" &>/dev/null
  echo -e "$OKBOLD$OKGREEN""[+] AssetFinder Found:$RESET $(wc -l < $ASSETFINDER_OUT)"
  echo
}

function run_findomain {
  echo "$OKBOLD$OKBLUE#### Running FindDomain ####$RESET"
  "$FINDOMAIN_BIN" -f "$WILDCARDS" -q -u "$FINDDOMAIN_OUT" &>/dev/null
  echo -e "$OKBOLD$OKGREEN""[+] FinDomain Found:$RESET $(wc -l < $FINDDOMAIN_OUT)"
  echo
}

function run_others {
  echo "$OKBOLD$OKBLUE#### Running GAU, WayBackURL, Crt ####$RESET"
  while read -r line; do
    "$GAU_BIN" --threads 50 --subs "$line" | "$ANEW_BIN" "$GAU_OUT" &>/dev/null
    cat "$GAU_OUT" | "$UNFURL_BIN" -u domains | sort -u -o "$SUBD_GAU_OUT" &>/dev/null
    "$WAYBACKURL_BIN" "$line" | "$ANEW_BIN" "$WAYBACKURL_OUT" &>/dev/null
    cat "$WAYBACKURL_OUT" | "$UNFURL_BIN" -u domains | sort -u -o "$SUBD_WAYBACKURL_OUT" &>/dev/null
    curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$line&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u -o "$RAW_DIR"/wayback-"$line".out &>/dev/null
    curl -sk "https://crt.sh/?q=%.$line&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | sort -u -o "$RAW_DIR"/crt-"$line".out &>/dev/null
    wget "https://crt.sh/?q=%.$line&output=json" -P "$RAW_DIR"/ &>/dev/null
    mv "$RAW_DIR"/index* "$RAW_DIR"/crt_"$line".json
    cat "$RAW_DIR"/crt_"$line".json | python3 -m json.tool | jq -r '.[].name_value' | sort -u -o "$RAW_DIR"/crt_"$line".out &>/dev/null
  done < "$WILDCARDS"
  cat "$RAW_DIR"/crt*.out | "$ANEW_BIN" "$CRT_OUT" &>/dev/null
  rm -r "$RAW_DIR"/*.json
  # echo -e "$OKBOLD$OKGREEN""[+] Gau:$RESET $(wc -l < $GAU_OUT)"
  # echo -e "$OKBOLD$OKGREEN""[+] Gau Found:$RESET $(wc -l < $SUBD_GAU_OUT)"
  # echo -e "$OKBOLD$OKGREEN""[+] WayBackURLS:$RESET $(wc -l < $WAYBACKURL_OUT)"
  # echo -e "$OKBOLD$OKGREEN""[+] WayBackURLS Found:$RESET $(wc -l < $SUBD_WAYBACKURL_OUT)"
  echo -e "$OKBOLD$OKGREEN""[+] Crt Found:$RESET $(wc -l < $CRT_OUT)"
  echo
}

function collect_subdomains {
  # # get_asn_cidr
  run_amass
  run_subfinder
  run_assetfinder
  run_findomain
  run_others
}

# SORT ALL SUB-DOMAINS
function run_sort {
  echo "$OKBOLD$OKBLUE#### Sorting Files ####$RESET"
  touch "$COLLECTED"
  cat "$RAW_DIR"/*.out | $ANEW_BIN "$COLLECTED" &>/dev/null 
  sort -u "$COLLECTED" > "$COLLECTED_SORTED"
  echo -e "$OKGREEN""[+] All Collected:$RESET $(wc -l < $COLLECTED)"
  #grep -F -vf  "$OUT_SCOPE" "$COLLECTED_SORTED" > "$COLLECTED_FINAL"
  echo
}

while [ -n "$1" ]; do
	case $1 in
		-df)
			WILDCARDS=$2
      banner
      checks
      create_folders
      collect_subdomains
      run_sort
			shift ;;
		-h|--help)
			USAGE;;
		# -v|--version)
		# 	echo "v$VERSION"
		# 	exit 0 ;;
		*)
			echo "[-] Unknown Option: $1"
			USAGE ;;
	esac
	shift
done
