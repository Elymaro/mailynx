#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[38;5;214m'
NC='\033[0m'

usage() {
    echo "Usage: $0 [-d domain.lab] | [-L domain_list.txt] [-o output.md] [-H]"
    echo "  -d  Single domain to check"
    echo "  -L  File containing list of domains"
    echo "  -o  Output file (default: markdown format)"
    echo "  -H  Generate HTML report instead of markdown"
    exit 1
}

# Parse input arguments
html_output=false
while getopts "d:L:o:H" opt; do
    case $opt in
        d) single_domain=$OPTARG ;;
        L) domain_list=$OPTARG ;;
        o) output_file=$OPTARG ;;
        H) html_output=true ;;
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

# Risk counters
low_risk=0
medium_risk=0
high_risk=0

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

calculate_risk() {
    local spf=$1
    local dkim=$2
    local dmarc=$3
    
    local nok_count=0
    [ "$spf" = "NOK" ] && ((nok_count++))
    [ "$dkim" = "NOK" ] && ((nok_count++))
    [ "$dmarc" = "NOK" ] && ((nok_count++))
    
    case $nok_count in
        0) echo "LOW" ;;
        1) echo "MEDIUM" ;;
        *) echo "HIGH" ;;
    esac
}

update_risk_counters() {
    local risk_level=$1
    case $risk_level in
        "LOW") ((low_risk++)) ;;
        "MEDIUM") ((medium_risk++)) ;;
        "HIGH") ((high_risk++)) ;;
    esac
}

append_report() {
    local domain=$1
    local spf=$2
    local dkim=$3
    local dmarc=$4

    local risk_level=$(calculate_risk "$spf" "$dkim" "$dmarc")
    update_risk_counters "$risk_level"

    if [ "$html_output" = true ]; then
        local spf_cell="$spf"
        local dkim_cell="$dkim"
        local dmarc_cell="$dmarc"
        
        if [ "$spf" = "NOK" ]; then
            spf_cell="<span style='color:red'>❌ NOK</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712' target='_blank'>Configurer SPF</a>)</small>"
        else
            spf_cell="<span style='color:green'>✅ OK</span>"
        fi
        if [ "$dkim" = "NOK" ]; then
            dkim_cell="<span style='color:red'>❌ NOK</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101' target='_blank'>Configurer DKIM</a>)</small>"
        else
            dkim_cell="<span style='color:green'>✅ OK</span>"
        fi
        if [ "$dmarc" = "NOK" ]; then
            dmarc_cell="<span style='color:red'>❌ NOK</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153' target='_blank'>Configurer DMARC</a>)</small>"
        else
            dmarc_cell="<span style='color:green'>✅ OK</span>"
        fi
        
        case $risk_level in
            "LOW") risk_cell="<span style='color:green'>🟢 LOW</span>" ;;
            "MEDIUM") risk_cell="<span style='color:orange'>🟡 MEDIUM</span>" ;;
            "HIGH") risk_cell="<span style='color:red'>🔴 HIGH</span>" ;;
        esac
        
        domains_table+="    <tr><td>$domain</td><td>$spf_cell</td><td>$dkim_cell</td><td>$dmarc_cell</td><td>$risk_cell</td></tr>"
    else
        local spf_cell="$spf"
        local dkim_cell="$dkim"
        local dmarc_cell="$dmarc"

        if [ "$spf" = "NOK" ]; then
            spf_cell="❌ NOK ([Configurer SPF](https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712))"
        else
            spf_cell="✅ OK"
        fi
        if [ "$dkim" = "NOK" ]; then
            dkim_cell="❌ NOK ([Configurer DKIM](https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101))"
        else
            dkim_cell="✅ OK"
        fi
        if [ "$dmarc" = "NOK" ]; then
            dmarc_cell="❌ NOK ([Configurer DMARC](https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153))"
        else
            dmarc_cell="✅ OK"
        fi

        case $risk_level in
            "LOW") risk_cell="🟢 LOW" ;;
            "MEDIUM") risk_cell="🟡 MEDIUM" ;;
            "HIGH") risk_cell="🔴 HIGH" ;;
        esac

        domains_table+="| $domain | $spf_cell | $dkim_cell | $dmarc_cell | $risk_cell
"
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
        spf_status="NOK"
        if [[ "$spf" == *"redirect="* ]]; then
            redirect_domain=$(echo "$spf" | sed -n 's/.*redirect=\([^ ]*\).*/\1/p')
            redirect_domain=${redirect_domain%\"}
            spf=$(dig "$redirect_domain" TXT +short | grep -i spf | tr -d '"')
        fi
        if [[ -n "$spf" ]] && [[ "$spf" =~ [\?\+\~]all ]]; then
            print_result "SPF" "NOK" "$spf" ""
            spf_status="NOK"
        elif [ -n "$spf" ]; then
            print_result "SPF" "OK" "$spf" ""
            spf_status="OK"
        else
            print_result "SPF" "NOK" "" ""
            spf_status="NOK"
        fi

        dkim_found=false
        dkim_status="NOK"
        for selector in "${selectors[@]}"; do
            dkim=$(dig "$selector._domainkey.$domain" TXT +short | grep -i dkim)
            if [ -n "$dkim" ]; then
                dkim_found=true
                dkim_status="OK"
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
            dkim_status="NOK"
        fi

        dmarc=$(dig "_dmarc.$domain" TXT +short)
        dmarc_status="NOK"
        if [[ -n "$dmarc" ]] && [[ "$dmarc" == *"p=none"* ]]; then
            print_result "DMARC" "NOK" "$dmarc" ""
            dmarc_status="NOK"
        elif [ -n "$dmarc" ]; then
            print_result "DMARC" "OK" "$dmarc" ""
            dmarc_status="OK"
        else
            print_result "DMARC" "NOK" "" ""
            dmarc_status="NOK"
        fi

        append_report "$domain" "$spf_status" "$dkim_status" "$dmarc_status"
    fi
}

generate_html_report() {
    local total_domains=$((low_risk + medium_risk + high_risk))
    
    cat << EOF
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mailynx Report - Security Analysis</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f7fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
        .header p { margin: 10px 0 0; opacity: 0.9; }
        .content { padding: 30px; }
        .risk-distribution { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .risk-card { background: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; border-left: 4px solid #ddd; }
        .risk-low { border-left-color: #28a745; }
        .risk-medium { border-left-color: #ffc107; }
        .risk-high { border-left-color: #dc3545; }
        .risk-card h3 { margin: 0 0 10px; font-size: 1.2em; }
        .risk-card .count { font-size: 2em; font-weight: bold; margin: 10px 0; }
        .risk-card .percentage { color: #666; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #495057; }
        tr:hover { background: #f8f9fa; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        small { font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Mailynx Report</h1>
            <p>Email Security Analysis - $(date)</p>
        </div>
        <div class="content">
            <h2>📊 Risk Distribution</h2>
            <div class="risk-distribution">
                <div class="risk-card risk-low">
                    <h3>🟢 Low Risk</h3>
                    <div class="count">$low_risk</div>
                    <div class="percentage">$([ $total_domains -gt 0 ] && echo "$((low_risk * 100 / total_domains))%" || echo "0%")</div>
                </div>
                <div class="risk-card risk-medium">
                    <h3>🟡 Medium Risk</h3>
                    <div class="count">$medium_risk</div>
                    <div class="percentage">$([ $total_domains -gt 0 ] && echo "$((medium_risk * 100 / total_domains))%" || echo "0%")</div>
                </div>
                <div class="risk-card risk-high">
                    <h3>🔴 High Risk</h3>
                    <div class="count">$high_risk</div>
                    <div class="percentage">$([ $total_domains -gt 0 ] && echo "$((high_risk * 100 / total_domains))%" || echo "0%")</div>
                </div>
            </div>
            
            <p><strong>Total domains analyzed:</strong> $total_domains</p>
            
            <h2>📋 Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>SPF</th>
                        <th>DKIM</th>
                        <th>DMARC</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
$domains_table                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOF
}

generate_markdown_report() {
    local total_domains=$((low_risk + medium_risk + high_risk))
    
    cat << EOF
# Mailynx Report

## Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| 🟢 LOW | $low_risk | $([ $total_domains -gt 0 ] && echo "$((low_risk * 100 / total_domains))%" || echo "0%") |
| 🟡 MEDIUM | $medium_risk | $([ $total_domains -gt 0 ] && echo "$((medium_risk * 100 / total_domains))%" || echo "0%") |
| 🔴 HIGH | $high_risk | $([ $total_domains -gt 0 ] && echo "$((high_risk * 100 / total_domains))%" || echo "0%") |

**Total domains analyzed:** $total_domains

## Detailed Results

| Domain | SPF | DKIM | DMARC | Risk Level |
|--------|-----|------|-------|------------|
$domains_table
EOF
}

# Initialize domains table
domains_table=""

if [ -n "$single_domain" ]; then
    check_domain "$single_domain"
elif [ -n "$domain_list" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        check_domain "$line"
    done < "$domain_list"
fi

# Generate and save report if output_file is set
if [ -n "$output_file" ]; then
    if [ "$html_output" = true ]; then
        generate_html_report > "$output_file"
    else
        generate_markdown_report > "$output_file"
    fi
    echo "Report saved to $output_file"
fi