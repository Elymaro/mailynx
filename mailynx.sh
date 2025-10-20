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
    echo "  -v  Verbose mode (display all analysed domains)"
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

if [ -n "$output_file" ]; then
    if [ -d "$output_file" ]; then
        echo "Error: $output_file is a directory!" >&2
        usage
    fi

    dir=$(dirname -- "$output_file")

    if [ ! -d "$dir" ]; then
        echo "Error: directory $dir does not exist for output file $output_file" >&2
        exit 1
    fi

    if [ ! -w "$dir" ]; then
        echo "Error: directory $dir is not writable" >&2
        exit 1
    fi
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
    local spf_status=$1
    local dkim_status=$2
    local dmarc_status=$3

    if [ "$dmarc_status" = "NOK" ]; then
        echo "HIGH"
        return
    fi

    if [ "$dmarc_status" = "MED" ]; then
        echo "MEDIUM"
        return
    fi

    if [ "$spf_status" = "OK" ] && [ "$dkim_status" = "OK" ]; then
        echo "LOW"
    elif [ "$spf_status" = "NOK" ] && [ "$dkim_status" = "OK" ]; then
        echo "LOW"
    else
        echo "MEDIUM"
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
    local spf_status=$2
    local spf_detailled=$3
    local dkim_status=$4
    local dkim_detailled=$5
    local dmarc_status=$6
    local dmarc_detailled=$7

    local risk_level=$(calculate_risk "$spf_status" "$dkim_status" "$dmarc_status")
    update_risk_counters "$risk_level"

    if [ "$html_output" = true ]; then
        local spf_cell="$spf_status"
        local dkim_cell="$dkim_status"
        local dmarc_cell="$dmarc_status"
        
        if [ "$spf_status" = "NOK" ]; then
            spf_cell="<span style='color:red'>❌ NOK</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712' target='_blank'>SPF configuration</a>)</small>"
        elif [ "$spf_status" = "MED" ]; then
            spf_cell="<span style='color:orange'>⚠️ MEDIUM</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712' target='_blank'>SPF recommandations</a>)</small>"
        else
            spf_cell="<span style='color:green'>✅ OK</span>"
        fi
        
        if [ "$dkim_status" = "NOK" ]; then
            dkim_cell="<span style='color:red'>❌ NOK</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101' target='_blank'>DKIM configuration</a>)</small>"
        elif [ "$dkim_status" = "MED" ]; then
            dkim_cell="<span style='color:orange'>⚠️ MEDIUM</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101' target='_blank'>DKIM recommandations</a>)</small>"
        else
            dkim_cell="<span style='color:green'>✅ OK</span>"
        fi
        
        if [ "$dmarc_status" = "NOK" ]; then
            dmarc_cell="<span style='color:red'>❌ NOK</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153' target='_blank'>DMARC configuration</a>)</small>"
        elif [ "$dmarc_status" = "MED" ]; then
            dmarc_cell="<span style='color:orange'>⚠️ MEDIUM</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153' target='_blank'>DMARC recommandations</a>)</small>"
        else
            dmarc_cell="<span style='color:green'>✅ OK</span>"
        fi
        
        case $risk_level in
            "LOW") risk_cell="<span style='color:green'>🟢 LOW</span>" ;;
            "MEDIUM") risk_cell="<span style='color:orange'>🟡 MEDIUM</span>" ;;
            "HIGH") risk_cell="<span style='color:red'>🔴 HIGH</span>" ;;
        esac
        
details_html=$(cat << EOF
<style>
.detail-box { border-radius:8px; border:1px solid #e6e9ed; background:#fbfcfd; padding:14px; }
.detail-head { font-weight:700; margin-bottom:8px; color:#2d3748; display:flex; justify-content:space-between; align-items:center; }
.detail-sub { color:#4a5568; font-size:0.95rem; margin-bottom:8px; margin-top:8px; }
.tech { margin-top:12px; margin-bottom:12px; background:#fff; border:1px solid #eef2f7; padding:1px 20px 1px 20px; border-radius:6px; font-family: Menlo, Monaco, monospace; font-size:0.88rem; color:#1f2937; white-space:pre-wrap; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:0.8rem; margin-left:6px; font-weight:400; }
.badge.ok { background:#e6ffed; color:#08660d; border:1px solid #b7f3c8; }
.badge.nok { background:#ffecec; color:#a61b1b; border:1px solid #f3c2c2; }
.muted { color:#2d3748; font-weight:400; }
.label { color:#6b7280; font-size:0.85rem; margin-right:6px; }
.u { text-decoration:underline; color:#374151; }
</style>

<div class="detail-box">
  <div><span class="label">Service: $service</span></div>

  <div class="detail-sub"><span class="u">Major controls:</span></div>
  <div class="tech">
SPF:  $( [ -n "$spf_detailled" ] && echo "<span class='muted'> ${spf_detailled}</span>" || echo "<span class='badge nok'>Not configured</span>" )
DKIM:   $( [ -n "$dkim_detailled" ] && echo "<span class='badge ok'>(RSA $dkim_detailled bits)</span>" || echo "<span class='badge nok'>Not configured</span>" )
DMARC:  $( [ -n "$dmarc_detailled" ] && echo "<span class='muted'> ${dmarc_detailled}</span>" || echo "<span class='badge nok'>Not configured</span>" )
  </div>

  <div class="detail-sub"><span class="u">Additional Security Protocols:</span></div>
  <div class="tech">
BIMI:    $( [ -n "$bimi" ] && [ "$bimi" != "TIMEOUT" ] && echo "<span class='badge ok'>✓ Configured</span>" || echo "<span class='badge nok'>✗ Not configured</span>" )
MTA-STS: $( [ -n "$mta_sts" ] && [ "$mta_sts" != "TIMEOUT" ] && echo "<span class='badge ok'>✓ Configured</span>" || echo "<span class='badge nok'>✗ Not configured</span>" )
TLS-RPT: $( [ -n "$tls_rpt" ] && [ "$tls_rpt" != "TIMEOUT" ] && echo "<span class='badge ok'>✓ Configured</span>" || echo "<span class='badge nok'>✗ Not configured</span>" )
DNSSEC:  $( [ -n "$dnssec" ] && [ "$dnssec" != "TIMEOUT" ] && echo "<span class='badge ok'>✓ Activated</span>" || echo "<span class='badge nok'>✗ Not activated</span>" )
  </div>
</div>
EOF
)

        domains_table+="
        <tr class='clickable' onclick=\"toggleDetails(this)\">
        <td>$domain</td><td>$spf_cell</td><td>$dkim_cell</td><td>$dmarc_cell</td><td>$risk_cell</td>
        </tr>
        <tr class='details-row'>
        <td colspan='5' class='details-cell'>$details_html</td>
        </tr>"
    else
        local spf_cell="$spf_status"
        local dkim_cell="$dkim_status"
        local dmarc_cell="$dmarc_status"

        if [ "$spf_status" = "NOK" ]; then
            spf_cell="❌ NOK ([SPF configuration](https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712))"
        elif [ "$spf_status" = "MED" ]; then
            spf_cell="⚠️ MEDIUM ([SPF recommandation](https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712))"
        else
            spf_cell="✅ OK"
        fi
        
        if [ "$dkim_status" = "NOK" ]; then
            dkim_cell="❌ NOK ([DKIM configuration](https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101))"
        elif [ "$dkim_status" = "MED" ]; then
            dkim_cell="⚠️ MEDIUM ([DKIM recommandation](https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101))"
        else
            dkim_cell="✅ OK"
        fi
        
        if [ "$dmarc_status" = "NOK" ]; then
            dmarc_cell="❌ NOK ([DMARC configuration](https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153))"
        elif [ "$dmarc_status" = "MED" ]; then
            dmarc_cell="⚠️ MEDIUM ([DMARC recommandation](https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153))"
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

    if [[ "$domain" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        ptr_record=$(dig -x "$domain" +nostats +nocomments +noquestion +noadditional | awk '/PTR/ {print $5}' | sed 's/\.$//')
        if [ -n "$ptr_record" ]; then
            [ "$verbose" = true ] && echo -e "${BLUE}[DEBUG] Reverse lookup found PTR: $ptr_record${NC}"
            domain="$ptr_record"
        else
            echo -e "${RED}[ERROR] No PTR record found for IP: $domain${NC}"
            return
        fi
    fi
    
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

    append_report "$domain" "$spf_status" "$spf" "$dkim_status" "$pk" "$dmarc_status" "$dmarc"
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
        .details-row { display: none; background: #fafafa; }
        .details-cell { padding: 0 20px 15px 20px; }
        tr.clickable:hover { background: #eef6ff; cursor: pointer; }
        pre { margin: 0; font-size: 0.9em; }
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
            <p>Generated by <a href="https://github.com/Elymaro/mailynx" target="_blank" rel="noopener noreferrer" style="color:inherit; text-decoration:none;"><u>Mailynx</u></a> - Mail DNS Records Audit Tool</p>
        </div>
    </div>
    <script>
        function toggleDetails(row) {
            const next = row.nextElementSibling;
            if (next && next.classList.contains('details-row')) {
                next.style.display = next.style.display === 'table-row' ? 'none' : 'table-row';
            }
        }
    </script>
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
*Generated by Mailynx - Mail DNS Records Audit Tool*
EOF
}

# Initialize domains table
domains_table=""

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                          Mailynx                          ║"
echo "║                                                           ║"
echo "║                 Mail DNS Records Audit Tool               ║"
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
