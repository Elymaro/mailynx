#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[38;5;214m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo "Usage: $0 [-d domain.lab] | [-L domain_list.txt] [-o output.md] [-H] [-v]"
    echo "  -d  Single domain to check"
    echo "  -L  File containing list of domains"
    echo "  -o  Output file (default: markdown format)"
    echo "  -H  Generate HTML report instead of markdown"
    echo "  -v  Verbose mode (show all DNS queries)"
    exit 1
}

# Parse input arguments
html_output=false
verbose=false
while getopts "d:L:o:Hv" opt; do
    case $opt in
        d) single_domain=$OPTARG ;;
        L) domain_list=$OPTARG ;;
        o) output_file=$OPTARG ;;
        H) html_output=true ;;
        v) verbose=true ;;
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

# Enhanced selector list for DKIM
selectors=(
    default dkim email emails google k1 k2 k3 key mail mails mxvault
    s s1 s2 s3 s4 selector selector1 selector2 selector3 selector4 smtp
    microsoft sendgrid mailgun amazonses mandrill postmark sparkpost
    dkim1 dkim2 dkim3 google1 google2 google3 mx proton zoho mta mailer 
    api relay web webmail mailjet mailchimp
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
        echo -e "$type: ${ORANGE}MEDIUM${NC} - $value $detailed_value"
    else
        echo -e "$type: ${RED}NOK${NC}  - $value $detailed_value"
    fi
}

calculate_risk() {
    local spf=$1
    local dkim=$2
    local dmarc=$3
    
    local nok_count=0
    local med_count=0
    
    [ "$spf" = "NOK" ] && ((nok_count++))
    [ "$spf" = "MED" ] && ((med_count++))
    [ "$dkim" = "NOK" ] && ((nok_count++))
    [ "$dkim" = "MED" ] && ((med_count++))
    [ "$dmarc" = "NOK" ] && ((nok_count++))
    [ "$dmarc" = "MED" ] && ((med_count++))
    
    if [ $nok_count -ge 2 ]; then
        echo "HIGH"
    elif [ $nok_count -eq 1 ] || [ $med_count -ge 2 ]; then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

update_risk_counters() {
    local risk_level=$1
    case $risk_level in
        "LOW") ((low_risk++)) ;;
        "MEDIUM") ((medium_risk++)) ;;
        "HIGH") ((high_risk++)) ;;
    esac
}

detect_email_service() {
    local mx=$1
    case "$mx" in
        *google.com*|*googlemail.com*) echo "Google Workspace" ;;
        *outlook.com*|*protection.outlook.com*) echo "Microsoft 365" ;;
        *mail.ovh.*|*mx*.ovh.*) echo "OVH" ;;
        *amazonses.com*) echo "Amazon SES" ;;
        *mailgun.org*) echo "Mailgun" ;;
        *sendgrid.net*) echo "SendGrid" ;;
        *protonmail.ch*) echo "ProtonMail" ;;
        *zoho.com*|*zoho.eu*) echo "Zoho Mail" ;;
        *) echo "Custom" ;;
    esac
}

dig_with_timeout() {
    timeout 5 dig +short "$@" 2>/dev/null || echo "TIMEOUT"
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
        elif [ "$spf" = "MED" ]; then
            spf_cell="<span style='color:orange'>⚠️ MEDIUM</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712' target='_blank'>Améliorer SPF</a>)</small>"
        else
            spf_cell="<span style='color:green'>✅ OK</span>"
        fi
        
        if [ "$dkim" = "NOK" ]; then
            dkim_cell="<span style='color:red'>❌ NOK</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101' target='_blank'>Configurer DKIM</a>)</small>"
        elif [ "$dkim" = "MED" ]; then
            dkim_cell="<span style='color:orange'>⚠️ MEDIUM</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101' target='_blank'>Améliorer DKIM</a>)</small>"
        else
            dkim_cell="<span style='color:green'>✅ OK</span>"
        fi
        
        if [ "$dmarc" = "NOK" ]; then
            dmarc_cell="<span style='color:red'>❌ NOK</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153' target='_blank'>Configurer DMARC</a>)</small>"
        elif [ "$dmarc" = "MED" ]; then
            dmarc_cell="<span style='color:orange'>⚠️ MEDIUM</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153' target='_blank'>Améliorer DMARC</a>)</small>"
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
            spf_cell="❌ NOK ([Configure SPF](https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712))"
        elif [ "$spf" = "MED" ]; then
            spf_cell="⚠️ MEDIUM ([Improve SPF](https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712))"
        else
            spf_cell="✅ OK"
        fi
        
        if [ "$dkim" = "NOK" ]; then
            dkim_cell="❌ NOK ([Configure DKIM](https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101))"
        elif [ "$dkim" = "MED" ]; then
            dkim_cell="⚠️ MEDIUM ([Improve DKIM](https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101))"
        else
            dkim_cell="✅ OK"
        fi
        
        if [ "$dmarc" = "NOK" ]; then
            dmarc_cell="❌ NOK ([Configure DMARC](https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153))"
        elif [ "$dmarc" = "MED" ]; then
            dmarc_cell="⚠️ MEDIUM ([Improve DMARC](https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153))"
        else
            dmarc_cell="✅ OK"
        fi

        case $risk_level in
            "LOW") risk_cell="🟢 LOW" ;;
            "MEDIUM") risk_cell="🟡 MEDIUM" ;;
            "HIGH") risk_cell="🔴 HIGH" ;;
        esac

        domains_table+="| $domain | $spf_cell | $dkim_cell | $dmarc_cell | $risk_cell |
"
    fi
}

check_domain() {
    local raw_domain=$1
    domain=$(sanitize_domain "$raw_domain")
    while [[ ! "${domain: -1}" =~ [a-zA-Z0-9] ]]; do
        domain="${domain%?}"
    done

    [ "$verbose" = true ] && echo -e "${BLUE}[DEBUG] Checking domain: $domain${NC}"

    # MX Records check - Simplified and more robust
    mx_records=$(dig "$domain" MX +nostats +nocomments +noquestion +noauthority +noadditional | grep -Ev "noadditional|global options" | grep MX)
    mx_records=$(echo "$mx_records" | tr -d '[:space:]')
    
    if [ -z "$mx_records" ]; then
        echo -e "${RED}[ERROR] No MX records found for domain: $domain${NC}"
        return
    fi

    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Found domain: $domain${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "MX: ${GREEN}Found${NC}"
    
    # Detect email service
    service=$(detect_email_service "$mx_records")
    echo -e "Service detected: ${GREEN}$service${NC}"

    # SPF Check
    spf=$(dig "$domain" TXT +short | grep -i "v=spf1")
    spf_status="NOK"
    
    if [[ "$spf" == *"redirect="* ]]; then
        redirect_domain=$(echo "$spf" | sed -n 's/.*redirect=\([^ ]*\).*/\1/p')
        redirect_domain=${redirect_domain%\"}
        spf=$(dig "$redirect_domain" TXT +short | grep -i "v=spf1" | tr -d '"')
    fi

    if [ -n "$spf" ]; then
        if [[ "$spf" =~ \+all ]]; then
            print_result "SPF" "NOK" "$spf" "${RED}(+all - accept ALL expeditors !)${NC}"
            spf_status="NOK"
        elif [[ "$spf" =~ \?all ]]; then
            print_result "SPF" "NOK" "$spf" "${RED}(?all - neutral, no protection)${NC}"
            spf_status="NOK"
        elif [[ "$spf" =~ ~all ]]; then
            print_result "SPF" "MED" "$spf" "${ORANGE}(~all - softfail)${NC}"
            spf_status="MED"
        elif [[ "$spf" =~ -all ]]; then
            print_result "SPF" "OK" "$spf" "${GREEN}(-all)${NC}"
            spf_status="OK"
        else
            print_result "SPF" "NOK" "$spf" "${RED}(no all mechanism)${NC}"
            spf_status="NOK"
        fi
    else
        print_result "SPF" "NOK" "Not configured" ""
        spf_status="NOK"
    fi

    # DKIM Check
    dkim_found=false
    dkim_status="NOK"
    
    for selector in "${selectors[@]}"; do
        dkim=$(dig "$selector._domainkey.$domain" TXT +short | grep -i "v=DKIM1")
        if [ -n "$dkim" ]; then
            dkim_found=true
            dkim_status="OK"
            public_key=$(echo "$dkim" | sed -n 's/.*p=\([^;]*\).*/\1/p' | tr -d '" ')
            
            if [ -n "$public_key" ]; then
                pk=$(echo "$public_key" | base64 -d 2>/dev/null | openssl rsa -inform DER -pubin -noout -text 2>/dev/null | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p')
                if [ -n "$pk" ]; then
                    if [ "$pk" -ge 2048 ]; then
                        print_result "DKIM ($selector)" "OK" "${GREEN}(RSA $pk bits)${NC}" ""
                    else
                        print_result "DKIM ($selector)" "MED" "${ORANGE}(RSA $pk bits - weak)${NC}" ""
                        dkim_status="MED"
                    fi
                fi
            fi
        fi
    done
    
    if [ "$dkim_found" == false ]; then
        print_result "DKIM" "NOK" "Not configured" ""
        dkim_status="NOK"
    fi

    # DMARC Check
    dmarc=$(dig "_dmarc.$domain" TXT +short | grep -i "v=DMARC1")
    dmarc_status="NOK"
    
    if [ -n "$dmarc" ]; then
        if [[ "$dmarc" == *"p=none"* ]]; then
            print_result "DMARC" "NOK" "$dmarc" "${RED}(monitoring only)${NC}"
            dmarc_status="NOK"
        elif [[ "$dmarc" == *"p=quarantine"* ]]; then
            print_result "DMARC" "MED" "$dmarc" "${ORANGE}(quarantine)${NC}"
            dmarc_status="MED"
        elif [[ "$dmarc" == *"p=reject"* ]]; then
            print_result "DMARC" "OK" "$dmarc" "${GREEN}(reject)${NC}"
            dmarc_status="OK"
        else
            print_result "DMARC" "NOK" "$dmarc" "${RED}(invalid policy)${NC}"
            dmarc_status="NOK"
        fi
    else
        print_result "DMARC" "NOK" "Not configured" ""
        dmarc_status="NOK"
    fi

    # Additional Security Checks
    echo -e "\n${YELLOW}Additional Security Protocols:${NC}"
    
    # BIMI Check
    bimi=$(dig_with_timeout "default._bimi.$domain" TXT +short 2>/dev/null)
    if [ -n "$bimi" ] && [ "$bimi" != "TIMEOUT" ]; then
        echo -e "BIMI: ${GREEN}✓ Configured${NC}"
    else
        echo -e "BIMI: ${RED}✗ Not configured${NC}"
    fi
    
    # MTA-STS Check
    mta_sts=$(dig_with_timeout "_mta-sts.$domain" TXT +short 2>/dev/null | grep -i "v=STSv1")
    if [ -n "$mta_sts" ] && [ "$mta_sts" != "TIMEOUT" ]; then
        echo -e "MTA-STS: ${GREEN}✓ Configured${NC}"
    else
        echo -e "MTA-STS: ${RED}✗ Not configured${NC}"
    fi
    
    # TLS-RPT Check
    tls_rpt=$(dig_with_timeout "_smtp._tls.$domain" TXT +short 2>/dev/null | grep -i "v=TLSRPTv1")
    if [ -n "$tls_rpt" ] && [ "$tls_rpt" != "TIMEOUT" ]; then
        echo -e "TLS-RPT: ${GREEN}✓ Configured${NC}"
    else
        echo -e "TLS-RPT: ${RED}✗ Not configured${NC}"
    fi
    
    # DNSSEC Check
    dnssec=$(dig_with_timeout "$domain" +dnssec +short 2>/dev/null | grep "RRSIG")
    if [ -n "$dnssec" ] && [ "$dnssec" != "TIMEOUT" ]; then
        echo -e "DNSSEC: ${GREEN}✓ Activated${NC}"
    else
        echo -e "DNSSEC: ${RED}✗ Not activated${NC}"
    fi

    append_report "$domain" "$spf_status" "$dkim_status" "$dmarc_status"
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
        .footer { text-align: center; padding: 20px; color: #666; font-size: 0.9em; border-top: 1px solid #eee; }
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
$domains_table
                </tbody>
            </table>
        </div>
        <div class="footer">
            <p>Generated by Mailynx - Email Security Auditing Tool</p>
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

---
*Generated by Mailynx - Email Security Auditing Tool*
EOF
}

# Initialize domains table
domains_table=""

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║                          Mailynx                          ║"
echo "║                                                           ║"
echo "║             Email Security Configuration Auditor          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ -n "$single_domain" ]; then
    check_domain "$single_domain"
elif [ -n "$domain_list" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue
        check_domain "$line"
    done < "$domain_list"
fi

echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Analysis Complete!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Generate and save report if output_file is set
if [ -n "$output_file" ]; then
    if [ "$html_output" = true ]; then
        generate_html_report > "$output_file"
        echo -e "${GREEN}HTML report saved to $output_file${NC}"
    else
        generate_markdown_report > "$output_file"
        echo -e "${GREEN}Markdown report saved to $output_file${NC}"
    fi
fi