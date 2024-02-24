#!/bin/bash

VERSION=1.0

#GET TARGET
function get_company {
  echo "Enter Company Name: " 
  read -r "TARGET"
  echo
}


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
  # "$AMASS_BIN" intel -whois -df in-scope -o "$AMASS_INTEL_OUT"              # Find Root Domains
  "$AMASS_BIN" enum -passive -df "$WILDCARDS" -o "$AMASS_ENUM_OUT"      # Find Subdomains
  echo -e "$OKGREEN""[+] JS:$RESET $(wc -l < $AMASS_ENUM_OUT)"
  echo
}

function run_subfinder {
  echo "$OKBOLD$OKBLUE#### Running SubFinder ####$RESET"
  "$SUBFINDER_BIN" -dL "$WILDCARDS" -all -t 100 -silent -o "$SUBFINDER_OUT"
  echo -e "$OKGREEN""[+] JS:$RESET $(wc -l < $SUBFINDER_BIN)"
  echo
}

function run_assetfinder {
  echo "$OKBOLD$OKBLUE#### Running AssetFinder ####$RESET"
  cat "$WILDCARDS" | "$ASSETFINDER_BIN" -subs-only > "$ASSETFINDER_OUT"
  echo -e "$OKGREEN""[+] JS:$RESET $(wc -l < $ASSETFINDER_OUT)"
  echo
}

function run_findomain {
  echo "$OKBOLD$OKBLUE#### Running FindDomain ####$RESET"
  "$FINDOMAIN_BIN" -f "$WILDCARDS" -q -u "$FINDDOMAIN_OUT"
  echo -e "$OKGREEN""[+] JS:$RESET $(wc -l < $FINDDOMAIN_OUT)"
  echo
}

function run_others {
  echo "$OKBOLD$OKBLUE#### Running GAU & WayBackURL####$RESET"
  while read -r line; do
    "$GAU_BIN" --threads 100 --subs "$line" > "$GAU_OUT"
    "$UNFURL_BIN" -u domains | sort -u -o "$SUBD_GAU_OUT"
    "$WAYBACKURL_BIN" "$line" > "$WAYBACKURL_OUT"
    "$UNFURL_BIN" -u domains | sort -u -o "$SUBD_WAYBACKURL_OUT"
    curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$line&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u -o "$RAW_DIR"/wayback-"$line".out
    curl -sk "https://crt.sh/?q=%.$line&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | sort -u -o "$RAW_DIR"/crt-"$line".out
  done < "$WILDCARDS"
  echo -e "$OKGREEN""[+] JS:$RESET $(wc -l < $GAU_OUT)"
  echo -e "$OKGREEN""[+] JS:$RESET $(wc -l < $SUBD_GAU_OUT)"
  echo -e "$OKGREEN""[+] JS:$RESET $(wc -l < $WAYBACKURL_OUT)"
  echo -e "$OKGREEN""[+] JS:$RESET $(wc -l < $SUBD_WAYBACKURL_OUT)"
  echo
}

function collect_subdomains {
  get_asn_cidr
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
  cat "$AMASS_ENUM_OUT" "$SUBFINDER_BIN" "$ASSETFINDER_OUT" "$FINDDOMAIN_OUT" "$SUBD_GAU_OUT" "$SUBD_WAYBACKURL_OUT" | $ANEW_BIN "$COLLECTED" &>/dev/null
  sort -u "$COLLECTED" > "$COLLECTED_SORTED"
  #grep -F -vf  "$OUT_SCOPE" "$COLLECTED_SORTED" > "$COLLECTED_FINAL"
  echo
}

# echo "#### Running ShuffleDNS ####"
# if [ -f $COLLECTED_SORTED ]; then
#   echo -e "$OKBOLD$OKGREEN Collected File Found $RESET"
#   "$SHUFFLEDNS_BIN" -l "$COLLECTED_SORTED" -r $WORDLISTS_DIR/custom-dns-list.txt -o "$DNS_ACTIVE" -silent
#   sort "$DNS_ACTIVE" > "$DNS_ACTIVE_SORTED"
#   echo "Done"
# else
#   echo -e "{$OKBOLD$OKRED}[Collected File Not Found]$RESET"
# fi
# echo

# echo "#### Running HTTProbe ####"
# if [ -f "$DNS_ACTIVE_SORTED" ]; then
#   echo -e "$OKGREEN DNS Active File Found $RESET"
#   touch "$ACTIVE"
#   cat "$DNS_ACTIVE_SORTED" | "$HTTPROBE_BIN" -prefer-https > "$ACTIVE"
#   sort "$ACTIVE" > "$ACTIVE_SORTED"
#   echo "Done"
# else
#   echo -e "$OKRED DNS Active File Not Found"
# fi
# echo

while [ -n "$1" ]; do
	case $1 in
		-df)
			WILDCARDS=$2
      get_company
      banner
      checks
      create_folders
      collect_subdomains
      run_sort
			shift ;;
		-h|--help)
			USAGE;;
		-v|--version)
			echo "v$VERSION"
			exit 0 ;;
		*)
			echo "[-] Unknown Option: $1"
			USAGE ;;
	esac
	shift
done

HTTPROBE(){                     
	cat "$RAW_DIR"/collected | $HTTPROBE_BIN -c 30 -prefer-https > "$ACTIVE_DIR/httprobe"
}

SHUFFLE_DNS() {
	$SHUFFLEDNS_BIN  -l $ACTIVE_DIR/httprobe -r custom-dns-list -o $ACTIVE_DIR/dns_resolved
}

HTTPX() {
	$HTTPX_BIN -l $ACTIVE_DIR/httprobe -mc 200,201,300,302,400,403 -o $ACTIVE_DIR/httpx_alive &>/dev/null
	$HTTPX_BIN -l $ACTIVE_DIR/httprobe -o $ACTIVE_DIR/httpx_all &>/dev/null
}

FIND_JS() { 
	cat $ACTIVE_DIR/httpx_all | hakrawler -d 5 -t 10  -scope subs -plain | $ANEW_BIN report/hakrawler.out &>/dev/null
	cat $ACTIVE_DIR/httpx_all | $SUBJS_BIN | $ANEW_BIN report/subjs.out &>/dev/null
	cat report/subjs.out | $ANEW_BIN report/links_all.out &>/dev/null
	cat report/hakrawler.out | cut -d "]" -f 2 | cut -d " " -f 2 | $ANEW_BIN report/links_all.out &>/dev/null
	sort -u report/links_all.out | $ANEW_BIN report/links_sorted.out &>/dev/null
	echo -e $green"[+] Links:$end $(wc -l < report/links_sorted.out)"
	while read domain; do
    	cat report/links_sorted.out | grep -Ei $domain | $ANEW_BIN report/links_sorted_domain.out &>/dev/null
	done < $file
	cat report/links_sorted_domain.out | grep -Ei "*.js" > report/js.out
	echo -e $green"[+] JS:$end $(wc -l < report/js.out)"
}

# function get_cidr {
#   while read -r line; do
#     res=$(host -t a "$line")
#     if [ $(echo "$res" | cut -d ' ' -f 3) == 'no' ]; then
#         echo "Not Found $WILDCARDS"
#     else
#         whois $(echo $res | cut -d ' ' -f 4) | grep "CIDR" | cut -d ':' -f 2 >> "$SUBDOMAINS_DIR"/ip_block
#         sed "s/^[ \t]*//" -i "$SUBDOMAINS_DIR"/ip_block
#         whois $("$SUBDOMAINS_DIR"/ip_block) | grep "CIDR" >> "$SUBDOMAINS_DIR"/cidr
#     fi
#     sleep 2
#   done < "$WILDCARDS"
# }

# while read -r line; do
#     cat cidr | $MAPCIDR_BIN -silent | $DNSX_BIN -ptr -resp-only -o test
#     sed -i "/\googleuser\b/d" test
# done < "$SUBDOMAINS"/cidr