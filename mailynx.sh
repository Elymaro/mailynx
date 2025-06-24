#!/bin/bash

#################################################################
#####  Developped by Aurélien BOURDOIS                      #####
#####  https://www.linkedin.com/in/aurelien-bourdois/       #####
#################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[38;5;214m'
NC='\033[0m'

usage() {
    echo "Usage: $0 [-d domain.lab] | [-L domain_list.txt]"
    exit 1
}

# Parse input arguments
while getopts "d:L:" opt; do
    case $opt in
        d) single_domain=$OPTARG ;;
        L) domain_list=$OPTARG ;;
        *) usage ;;
    esac
done

if [ -n "$single_domain" ] && [ -n "$domain_list" ]; then
    echo "Error: Use either -d or -L, not both."
    usage
fi

if [ -z "$single_domain" ] && [ -z "$domain_list" ]; then
    usage
fi

if [ -n "$domain_list" ] && [ ! -f "$domain_list" ]; then
    echo "File $domain_list not found!"
    exit 1
fi

# Selector list for DKIM
selectors=(
    default dkim email emails google k1 key mail mails mxvault
    s s1 s2 s3 s4 selector selector1 selector2 selector3 selector4 smtp
)

sanitize_domain() {
    local raw_domain=$1
    echo "$raw_domain" | sed -E 's~^https?://~~' | sed -E 's~/.*~~'
}

print_result() {
    local type=$1
    local status=$2
    local value=$3
    local detailed_value=$4
    if [ "$status" == "OK" ]; then
        echo -e "$type: ${GREEN}OK${NC} - $value $detailed_value"
    elif [ "$status" == "MED" ]; then
        echo -e "$type: ${ORANGE}OK${NC} - $value $detailed_value"
    else
        echo -e "$type: ${RED}NOK${NC}  - $value $detailed_value"
    fi
}

check_domain() {
    local raw_domain=$1
    domain=$(sanitize_domain "$raw_domain")
    while [[ ! "${domain: -1}" =~ [a-zA-Z0-9] ]]; do
        domain="${domain%?}"
    done

    mx_records=$(dig "$domain" MX +nostats +nocomments +noquestion +noauthority +noadditional | grep -Ev "noadditional|global options" | grep MX)
    mx_records=$(echo "$mx_records" | tr -d '[:space:]')
    if [ -n "$mx_records" ]; then

        echo -e "\nFound domain: $domain"
        echo -e "MX: ${GREEN}Found${NC}"

        spf=$(dig "$domain" TXT +short | grep -i spf)

        if [[ "$spf" == *"redirect="* ]]; then
            redirect_domain=$(echo "$spf" | sed -n 's/.*redirect=\([^ ]*\).*/\1/p')
            redirect_domain=${redirect_domain%\"}
            spf=$(dig "$redirect_domain" TXT +short | grep -i spf | tr -d '"')
        fi
        if [[ -n "$spf" ]] && [[ "$spf" =~ [\?\+\~]all ]]; then
            print_result "SPF" "NOK" "$spf" ""
        elif [ -n "$spf" ]; then
            print_result "SPF" "OK" "$spf" ""
        else
            print_result "SPF" "NOK" "" ""
        fi

        dkim_found=false
        for selector in "${selectors[@]}"; do
            dkim=$(dig "$selector._domainkey.$domain" TXT +short | grep -i dkim)
            if [ -n "$dkim" ]; then
                dkim_found=true
                public_key=$(echo "$dkim" | sed -n 's/.*p=\([^;]*\).*/\1/p' | tr -d '" ')
                if [ -n "$public_key" ]; then
                    pk=$(echo "$public_key" | base64 -d 2>/dev/null | openssl rsa -inform DER -pubin -noout -text 2>/dev/null | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p')
                    if [ "$pk" -gt 1024 ]; then
                        print_result "DKIM ($selector)" "OK" "${GREEN}(RSA $pk bits)${NC}" "$dkim"
                    else
                        print_result "DKIM ($selector)" "OK" "${ORANGE}(RSA $pk bits)${NC}" "$dkim"
                    fi
                else
                    print_result "DKIM ($selector)" "OK" "${ORANGE}(NULL)${NC}" "$dkim"
                fi
            fi
        done
        if [ "$dkim_found" == false ]; then
            print_result "DKIM" "NOK" "" ""
        fi

        dmarc=$(dig "_dmarc.$domain" TXT +short)
        if [[ -n "$dmarc" ]] && [[ "$dmarc" == *"p=none"* ]]; then
            print_result "DMARC" "NOK" "$dmarc" ""
        elif [ -n "$dmarc" ]; then
            print_result "DMARC" "OK" "$dmarc" ""
        else
            print_result "DMARC" "NOK" "" ""
        fi
    fi
}

if [ -n "$single_domain" ]; then
    check_domain "$single_domain"
elif [ -n "$domain_list" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        check_domain "$line"
    done < "$domain_list"
fi
