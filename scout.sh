#!/bin/bash
VERSION=1.1

#VARS
RESET="\e[0m"
BOLD="\033[01;01m"
RED="\033[0;31m"
GREEN="\033[0;32m"
BLUE="\033[1;34m"

CURRENTDATE=`date +"%Y-%m-%d_%T"`

#DIRECTORIES
INSTALL_DIR=~/scout
TOOLS_DIR="$INSTALL_DIR"/tools
BIN_DIR="$TOOLS_DIR"/bin
WORDLISTS_DIR="$TOOLS_DIR"/wordlists
WORKSPACE_DIR="$INSTALL_DIR"/workspace
OUTPUT_DIR="$WORKSPACE_DIR"/"output_$CURRENTDATE"
SUBDOMAINS_DIR="$OUTPUT_DIR"/subdomains
RAW_DIR="$SUBDOMAINS_DIR"/raw
COLLECTED_DIR="$SUBDOMAINS_DIR"/collected
FINAL_DIR="$SUBDOMAINS_DIR"/final

BANNER(){
  echo -e "${BOLD}${OKORANGE}" 
  echo -e "${BOLD}                      _   "
  echo -e "${BOLD}                     | |  "
  echo -e "${BOLD}  ___  ___ ___  _   _| |_ "
  echo -e "${BOLD} / __|/ __/ _ \| | | | __|"
  echo -e "${BOLD} \__ \ (_| (_) | |_| | |_ "
  echo -e "${BOLD} |___/\___\___/ \__,_|\__|${RESET}"
  echo -e "${BOLD}               :-By Ghost"
  echo -e "${RESET}"
  echo ""
  echo -e "${BOLD} LEGENDS:"
  echo -e "${BOLD}${BLUE} Blue = Script Running ${RESET}"
  echo -e "${BOLD}${GREEN} Green = Everything Fine ${RESET}"
  echo -e "${BOLD}${RED} Red = ERROR ${RESET}"
  echo -e
}

USAGE(){
	echo "Usage: "
  echo "$0 [-d domain[,domain2,...]] [-f file] ..."
  echo -e
  echo "-d domain   Add a domain"
  echo "-f file     Load domains from a file (one per line)"
  echo "-h          Show help"
  echo "-v          Show version"
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
  #CHECK INTERNET
  echo -e "${BLUE} Checking Internet Connection ${RESET}"
  wget -q --spider http://google.com
  if [ $? -eq 0 ]; then
    echo -e "${GREEN} **Online** ${RESET}"
  else
    echo -e "${RED} !!Offline!! ${RESET}"
    echo -e "${RED} !!Connect to Internet and rerun the script!! ${RESET}"
    exit
  fi
  echo
  sleep 0.5
}

cf=false
#CREATE FOLDERS 
function create_folders {
  echo -e "${BLUE} Creating Folders ${RESET}"
  mkdir -p "$OUTPUT_DIR" "$SUBDOMAINS_DIR" "$RAW_DIR" "$COLLECTED_DIR" "$FINAL_DIR"
  echo
}

function collect_subdomains {
  while read -r domain; do
  STARTSCRIPT=$(date +%s)
    mkdir -p $RAW_DIR/"$domain"
    echo -e "${BLUE}!!Checking: "$domain"!! ${RESET}"
    echo -e

    # SubFinder
    start=$(date +%s)
    echo -e "${BLUE} #### Running SubFinder for "$domain" #### ${RESET}"
    touch $RAW_DIR/"$domain"/subfinder.out
    "$BIN_DIR"/subfinder -d "$domain" -all -o $RAW_DIR/"$domain"/subfinder.out &>/dev/null
    end=$(date +%s)
    echo -e "${GREEN}[+] SubFinder Found " $(wc -l $RAW_DIR/"$domain"/subfinder.out | awk '{print $1}')" Subdomains in $((end - start)) seconds ${RESET}"
    echo

    # Assetfinder
    start=$(date +%s)
    echo -e "${BLUE} #### Running AssetFinder for "$domain" ####${RESET}"
    touch $RAW_DIR/"$domain"/assetfinder.out
    "$BIN_DIR"/assetfinder -subs-only "$domain" | sort -u > $RAW_DIR/"$domain"/assetfinder.out
    end=$(date +%s)
    echo -e "${GREEN}[+] AssetFinder Found " $(wc -l $RAW_DIR/"$domain"/assetfinder.out | awk '{print $1}')" Subdomains in $((end - start)) seconds ${RESET}"
    echo

    # Findomain
    start=$(date +%s)
    echo -e "${BLUE} #### Running FindDomain for "$domain" ####${RESET}"
    touch $RAW_DIR/"$domain"/findomain.out
    "$BIN_DIR"/findomain -t "$domain" -u $RAW_DIR/"$domain"/findomain.out &>/dev/null
    end=$(date +%s)
    echo -e "${GREEN}[+] FindDomain Found " $(wc -l $RAW_DIR/"$domain"/findomain.out | awk '{print $1}')" Subdomains in $((end - start)) seconds ${RESET}"
    echo

    # GAU
    start=$(date +%s)
    echo -e "${BLUE} #### Running GAU for "$domain" ####${RESET}"
    touch $RAW_DIR/"$domain"/gau.out
    echo "$domain" | "$BIN_DIR"/gau | $BIN_DIR/unfurl domain | sort -u > $RAW_DIR/"$domain"/gau.out
    end=$(date +%s)
    echo -e "${GREEN}[+] GAU Found " $(wc -l $RAW_DIR/"$domain"/gau.out | awk '{print $1}')" Subdomains in $((end - start)) seconds ${RESET}"
    echo  

    # WayBackURLS      
    start=$(date +%s) 
    echo -e "${BLUE} #### Running WAYBACKURLS for "$domain" ####${RESET}"
    touch $RAW_DIR/"$domain"/waybackurls.out
    echo "$domain" | "$BIN_DIR"/waybackurls | $BIN_DIR/unfurl domain | sort -u > $RAW_DIR/"$domain"/waybackurls.out
    end=$(date +%s)
    echo -e "${GREEN}[+] WAYBACKURLS Found " $(wc -l $RAW_DIR/"$domain"/waybackurls.out | awk '{print $1}')" Subdomains in $((end - start)) seconds ${RESET}"
    echo

    # Sublist3r
    start=$(date +%s) 
    echo -e "${BLUE} #### Running Sublist3r for "$domain" ####${RESET}"
    touch $RAW_DIR/"$domain"/sublit3r.out
    python3 $BIN_DIR/sublister/sublist3r.py -d "$domain" -o $RAW_DIR/"$domain"/sublit3r.out >/dev/null 2>&1
    end=$(date +%s)
    echo -e "${GREEN}[+] Sublist3r Found " $(wc -l $RAW_DIR/"$domain"/sublit3r.out | awk '{print $1}')" Subdomains in $((end - start)) seconds ${RESET}"
    echo

    # WebArchive
    start=$(date +%s) 
    echo -e "${BLUE} #### Running WebArchive for "$domain" ####${RESET}"
    touch $RAW_DIR/"$domain"/webarchive.out
    curl -sk "http://web.archive.org/cdx/search/cdx?url=*."$domain"&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u > $RAW_DIR/"$domain"/webarchive.out
    end=$(date +%s)
    echo -e "${GREEN}[+] WebArchive Found " $(wc -l $RAW_DIR/"$domain"/webarchive.out | awk '{print $1}')" Subdomains in $((end - start)) seconds ${RESET}"
    echo

    # CRTSH
    start=$(date +%s) 
    echo -e "${BLUE} #### Running CRTSH for "$domain" ####${RESET}"
    touch $RAW_DIR/"$domain"/crtsh.out
    curl -sk "https://crt.sh/?q=%."$domain"&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | sort -u > $RAW_DIR/"$domain"/crtsh.out
    end=$(date +%s)
    echo -e "${GREEN}[+] Crt Found " $(wc -l $RAW_DIR/"$domain"/crtsh.out | awk '{print $1}')" Subdomains in $((end - start)) seconds ${RESET}"
    echo

    # # AMASS
    # start=$(date +%s) 
    # echo -e "${BLUE} #### Running Amass for "$domain" in background ####${RESET}"
    # touch $RAW_DIR/"$domain"/amass.out
    # $BIN_DIR/amass enum -d "$domain" | awk '{for(i=1;i<=NF;i++) if($i ~ /'$domain'/) print $i}' | sort -u > $RAW_DIR/"$domain"/amass.out &>/dev/null
    # end=$(date +%s)
    # echo -e "${GREEN}[+] Amass Found " $(wc -l < $RAW_DIR/"$domain"/amass.out | awk '{print $1}')" Subdomains in $((end - start)) seconds ${RESET}"
    # echo

    touch "$COLLECTED_DIR"/"$domain"_all.out
    cat "$RAW_DIR"/"$domain"/*.out | $BIN_DIR/unfurl domain | sort -u > "$COLLECTED_DIR"/"$domain"_all.out
    echo -e "${GREEN}[+] All Subdomains Found for "$domain":${RESET}" $(wc -l "$COLLECTED_DIR"/"$domain"_all.out | awk '{print $1}')
    echo
    done < "$WILDCARDS"
  ENDSCRIPT=$(date +%s)
  echo -e "${GREEN} Subdomain Scanning took "$((ENDSCRIPT - STARTSCRIPT))" seconds ${RESET}"
}

function collect_live {
  touch "$COLLECTED_DIR"/httpx_all.out.json
  $BIN_DIR/httpx -l "$COLLECTED_DIR"/"$domain"_all.out -sc -title -server -td -ip -cname -efqdn -asn -cdn -probe -favicon -pa -fr -j "$COLLECTED_DIR"/httpx_all.out.json
}

# function passive_recursive {
#     for sub in $( ( cat "$COLLECTED" | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat "$COLLECTED" | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
#         "$SUBFINDER_BIN" -d "$sub" -silent -max-time 2 | anew -q passive_recursive.txt
#         "$ASSETFINDER_BIN" --subs-only "$sub" | anew -q passive_recursive.txt
#         "$AMASS_BIN" enum -timeout 5 -passive -d "$sub" | anew -q passive_recursive.txt
#         "$FINDOMAIN_BIN" --quiet -t "$sub" | anew -q passive_recursive.txt
#     done
# }

while getopts ":d:f:hv" OPTION; do
  case $OPTION in
    d)
      echo "$OPTARG" > "$INSTALL_DIR/domain"
      WILDCARDS="$INSTALL_DIR/domain"
      BANNER
      CHECKS
      create_folders
      collect_subdomains
      collect_live
      ;;
      
    f)
      WILDCARDS="$OPTARG"
      BANNER
      CHECKS
      create_folders
      collect_subdomains
      collect_live
      ;;
      
    h)
      BANNER
      USAGE
      exit 0
      ;;
      
    v)
      BANNER
      echo
      echo "Current Version is v$VERSION"
      exit 0
      ;;
      
    :)
      echo "[-] Option -$OPTARG requires an argument." >&2
      BANNER
      USAGE
      exit 1
      ;;
      
    \?)
      echo "[-] Unknown option: -$OPTARG" >&2
      BANNER
      USAGE
      exit 1
      ;;
  esac
done
