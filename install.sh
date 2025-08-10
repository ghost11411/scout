#!/bin/bash

VERSION=1.0

#VARS
RESET="\e[0m"
OKBOLD="\033[01;01m"
OKRED="\033[0;31m"
OKGREEN="\033[0;32m"
OKBLUE="\033[1;34m"

CURRENTDATE=`date +"%Y_-%m_-%d_%T"`

#DIRECTORIES
INSTALL_DIR=/root/scout
TOOLS_DIR="$INSTALL_DIR"/tools
BIN_DIR="$TOOLS_DIR"/bin
WORDLISTS_DIR="$TOOLS_DIR"/wordlists
WORKSPACE_DIR="$INSTALL_DIR"/workspace
OUTPUT_DIR="$WORKSPACE_DIR"/"scout_output_$CURRENTDATE"
SUBDOMAINS_DIR="$OUTPUT_DIR"/subdomains

domain=''

BANNER(){
  echo -e "${OKBOLD}${OKORANGE}" 
  echo -e "${OKBOLD}                      _   "
  echo -e "${OKBOLD}                     | |  "
  echo -e "${OKBOLD}  ___  ___ ___  _   _| |_ "
  echo -e "${OKBOLD} / __|/ __/ _ \| | | | __|"
  echo -e "${OKBOLD} \__ \ (_| (_) | |_| | |_ "
  echo -e "${OKBOLD} |___/\___\___/ \__,_|\__|${RESET}"
  echo -e "${OKBOLD}               :-By Ghost"
  echo -e "${RESET}"
  echo ""
  echo -e "${OKBOLD} LEGENDS:"
  echo -e "${OKBOLD}${OKBLUE} Blue = Script Running ${RESET}"
  echo -e "${OKBOLD}${OKGREEN} Green = Everything Fine ${RESET}"
  echo -e "${OKBOLD}${OKRED} Red = ERROR ${RESET}"
}

USAGE(){
	while read -r line; do
		printf "%b\n" "$line"
	done <<-EOF
	${OKRED}\r
	\r${OKBOLD}${OKBLUE}Options${RESET}:
	\r    -df         - File of Domains [Required]
	\r    -h          - Displays this help message and exit.
	\r    -v          - Displays the version and exit.

	\r${OKBOLD}${OKBLUE}Examples${RESET}: 
	\r    - To run scout.sh against a list of domains:
	\r    ./scout.sh -df domains.txt
EOF
	exit 1
}

# IF NO ARGS, SHOW USAGE
if [ $# -eq 0 ]; then
    BANNER
    USAGE
    exit 1
fi

#Basic Checks
CHECKS(){
  echo -e 
  echo -e "${OKBOLD}${OKBLUE} [*] Running Script ${RESET}"
  echo 
  sleep 0.5

#CHECK ROOT
  echo -e "${OKBLUE} Checking Root Permissions ${RESET}"
  sleep 0.5
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
      echo -e "${OKGREEN} **Online** ${RESET}"
  else
      echo -e "${OKRED} !!Offline!! ${RESET}"
      echo -e "${OKRED} !!Connect to Internet and rerun the script!! ${RESET}"
      exit
  fi
  sleep 0.5
  # clear
}

#CREATE FOLDERS 
function create_folders {
  mkdir -p "$OUTPUT_DIR"
  # if [ -d "$OUTPUT_DIR" ]; then
  #   echo "$OUTPUT_DIR does exist."
  # fi
  mkdir -p "$SUBDOMAINS_DIR"
  # if [ -d "$SUBDOMAINS_DIR" ]; then
  #   echo "$SUBDOMAINS_DIR does exist."
  # fi
  echo
}

function collect_subdomains {
    while read -r domain; do
        echo -e "${OKBOLD}${OKBLUE} !!Checking $domain!! ${RESET}"
        echo "${OKBOLD}${OKBLUE}#### Running Amass ####${RESET}"
        sudo "$AMASS_BIN" enum -passive -timeout 5 -d "$domain" -o "$SUBDOMAINS_DIR"/amass$domain.out &>/dev/null
        echo -e "${OKBOLD}${OKGREEN}""[+] Amass Found:${RESET} $(wc -l < "$SUBDOMAINS_DIR"/amass$domain.out)"
        echo 
        # echo -e "${OKBOLD}${OKBLUE}#### Running SubFinder #### ${RESET}"
        # echo "$domain" | "$BIN_DIR"/subfinder -all -silent | sort -u > "$SUBFINDER_OUT"
        # echo -e "${OKBOLD}${OKGREEN}[+] SubFinder Found:${RESET} $(wc -l "$SUBFINDER_OUT")"
        # echo
        # echo -e "${OKBOLD}${OKBLUE}#### Running AssetFinder ####${RESET}"
        # echo "$domain" | "$BIN_DIR"/assetfinder -subs-only | sort -u > "$ASSETFINDER_OUT"
        # echo -e "${OKBOLD}${OKGREEN}[+] AssetFinder Found:${RESET} $(wc -l "$ASSETFINDER_OUT")"
        # echo
        # echo -e "${OKBOLD}${OKBLUE}#### Running FindDomain ####${RESET}"
        # "$BIN_DIR"/findomain -q -t "$domain" -u > "$FINDDOMAIN_OUT"
        # echo -e "${OKBOLD}${OKGREEN}[+] FinDomain Found:${RESET} $(wc -l "$FINDDOMAIN_OUT")"
        # echo
        # echo -e "${OKBOLD}${OKBLUE}#### Running GAUPLUS ####${RESET}"
        # echo "$domain" | "$BIN_DIR"/gauplus | $BIN_DIR/unfurl domain | sort -u > "$GAUPLUS_OUT"
        # echo -e "${OKBOLD}${OKGREEN}[+] GAUPLUS Found:${RESET} $(wc -l "$GAUPLUS_OUT")"
        # echo         
        # echo -e "${OKBOLD}${OKBLUE}#### Running WAYBACKURLS ####${RESET}"
        # echo "$domain" | "$BIN_DIR"/waybackurls | $BIN_DIR/unfurl domain | sort -u > "$WAYBACKURLS_OUT"
        # echo -e "${OKBOLD}${OKGREEN}[+] WAYBACKURLS Found:${RESET} $(wc -l "$WAYBACKURLS_OUT")"
        # echo
        # curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u >"$WEBARCHIVE_OUT"
        # echo -e "${OKBOLD}${OKGREEN}[+] WEBARCHIVE Found:${RESET} $(wc -l "$WEBARCHIVE_OUT")"
        # curl -sk "https://crt.sh/?q=%.$domain&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | sort -u > "$CRTSH_OUT"
        # echo -e "${OKBOLD}${OKGREEN}[+] Crt Found:${RESET} $(wc -l "$CRT_OUT")"
    done < "$WILDCARDS"
}

# # SORT ALL SUB-DOMAINS
# function run_sort {
#   echo "${OKBOLD}${OKBLUE}#### Sorting Files ####${RESET}"
#   touch "$COLLECTED"
#   cat "$RAW_DIR"/*.out | $ANEW_BIN "$COLLECTED" &>/dev/null 
#   sort -u "$COLLECTED" > "$COLLECTED_SORTED"
#   echo -e "${OKGREEN}""[+] All Collected:${RESET} $(wc -l < $COLLECTED)"
#   #grep -F -vf  "$OUT_SCOPE" "$COLLECTED_SORTED" > "$COLLECTED_FINAL"
#   echo
# }

# function passive_recursive {
#     for sub in $( ( cat "$COLLECTED" | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat "$COLLECTED" | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
#         "$SUBFINDER_BIN" -d "$sub" -silent -max-time 2 | anew -q passive_recursive.txt
#         "$ASSETFINDER_BIN" --subs-only "$sub" | anew -q passive_recursive.txt
#         "$AMASS_BIN" enum -timeout 5 -passive -d "$sub" | anew -q passive_recursive.txt
#         "$FINDOMAIN_BIN" --quiet -t "$sub" | anew -q passive_recursive.txt
#     done
# }

while [ -n "$1" ]; do
	case $1 in
		-df)
			WILDCARDS=$2
      BANNER
      CHECKS
      create_folders
      collect_subdomains
			shift ;;
		-h|--help)
      BANNER
			USAGE;;
		-v|--version)
      BANNER
      echo -e
			echo "Current Version is v$VERSION"
			exit 0 ;;
		*)
			echo "[-] Unknown Option: $1"
      BANNER
			USAGE ;;
	esac
	shift
done
