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
moderate_risk=0
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
        echo -e "$type: ${ORANGE}MODERATE${NC} - $value $detailed_value"
    else
        echo -e "$type: ${RED}NOK${NC} - $value $detailed_value"
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
        echo "MODERATE"
        return
    fi

    if [ "$spf_status" = "OK" ] && [ "$dkim_status" = "OK" ]; then
        echo "LOW"
    elif [ "$spf_status" = "NOK" ] && [ "$dkim_status" = "OK" ]; then
        echo "LOW"
    else
        echo "MODERATE"
    fi
}

update_risk_counters() {
    local risk_level=$1
    case $risk_level in
        "LOW") ((low_risk++)) ;;
        "MODERATE") ((moderate_risk++)) ;;
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
    timeout 1 dig "$@" 2>/dev/null || echo "TIMEOUT"
}

append_report() {
    local domain=$1
    local spf_status=$2
    local spf_detailled=$3
    local spf_reason=$4
    local dkim_status=$5
    local dkim_detailled=$6
    local dmarc_status=$7
    local dmarc_detailled=$8

    local risk_level=$(calculate_risk "$spf_status" "$dkim_status" "$dmarc_status")
    update_risk_counters "$risk_level"

    spf_csv="$spf_status"
    local spf_reason_label=""
    case "$spf_reason" in
        multiple_records) spf_reason_label="multiple SPF records" ;;
        plus_all) spf_reason_label="+all - accept all senders" ;;
        neutral_all) spf_reason_label="?all - neutral, no protection" ;;
        missing_all) spf_reason_label="missing 'all' mechanism" ;;
        not_configured) spf_reason_label="not configured" ;;
        softfail) spf_reason_label="~all - softfail" ;;
        hardfail) spf_reason_label="-all" ;;
        *) spf_reason_label="invalid configuration" ;;
    esac
    
    dkim_csv="$dkim_status"
    local dkim_reason_label=""
    case "$dkim_status" in
        OK) dkim_reason_label="RSA >2048 bits" ;;
        MED) dkim_reason_label="RSA <2048 bits" ;;
        NOK) dkim_reason_label="not configured" ;;
    esac
    dmarc_csv="$dmarc_status"
    
    case "$spf_status" in
        OK)
            spf_csv="OK"
            ;;
        MED)
            spf_csv="MODERATE ($spf_reason_label)"
            ;;
        NOK)
            spf_csv="NOK ($spf_reason_label)"
            ;;
    esac

    case "$dkim_status" in
        OK)
            dkim_csv="OK"
            ;;
        MED)
            dkim_csv="MODERATE ($dkim_reason_label)"
            ;;
        NOK)
            dkim_csv="NOK ($dkim_reason_label)"
            ;;
    esac

    case "$dmarc_status" in
        OK)
            dmarc_csv="OK"
            ;;
        MED)
            dmarc_csv="MODERATE (quarantine)"
            ;;
        NOK)
            if [[ "$dmarc_detailled" == *"p=none"* ]]; then
                dmarc_csv="NOK (monitoring only)"
            else
                dmarc_csv="NOK (not configured)"
            fi
            ;;
    esac

    csv_table+="\"$domain\",\"$service\",\"$spf_csv\",\"$dkim_csv\",\"$dmarc_csv\",\"$risk_level\""$'\n'

    if [ "$html_output" = true ]; then
        local spf_cell="$spf_status"
        local dkim_cell="$dkim_status"
        local dmarc_cell="$dmarc_status"
        
        if [ "$spf_status" = "NOK" ]; then
            spf_cell="<span style='color:red'>❌ NOK</span> <small>($spf_reason_label - <a href='https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712' target='_blank'>SPF configuration</a>)</small>"
        elif [ "$spf_status" = "MED" ]; then
            spf_cell="<span style='color:orange'>⚠️ MODERATE</span> <small>($spf_reason_label - <a href='https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712' target='_blank'>SPF recommandations</a>)</small>"
        else
            spf_cell="<span style='color:green'>✅ OK</span>"
        fi
        
        if [ "$dkim_status" = "NOK" ]; then
            dkim_cell="<span style='color:red'>❌ NOK</span> <small>($dkim_reason_label - <a href='https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101' target='_blank'>DKIM configuration</a>)</small>"
        elif [ "$dkim_status" = "MED" ]; then
            dkim_cell="<span style='color:orange'>⚠️ MODERATE</span> <small>($dkim_reason_label - <a href='https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101' target='_blank'>DKIM recommandations</a>)</small>"
        else
            dkim_cell="<span style='color:green'>✅ OK</span>"
        fi
        
        if [ "$dmarc_status" = "NOK" ]; then
            dmarc_cell="<span style='color:red'>❌ NOK</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153' target='_blank'>DMARC configuration</a>)</small>"
        elif [ "$dmarc_status" = "MED" ]; then
            dmarc_cell="<span style='color:orange'>⚠️ MODERATE</span> <small>(<a href='https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153' target='_blank'>DMARC recommandations</a>)</small>"
        else
            dmarc_cell="<span style='color:green'>✅ OK</span>"
        fi
        
        case $risk_level in
            "LOW") risk_cell="<span style='color:green'>🟢 LOW</span>" ;;
            "MODERATE") risk_cell="<span style='color:orange'>🟡 MODERATE</span>" ;;
            "HIGH") risk_cell="<span style='color:red'>🔴 HIGH</span>" ;;
        esac

spf_detail_badge=""
dkim_detail_badge=""
dmarc_detail_badge=""

case "$spf_status" in
    OK) spf_detail_badge="<span class='badge ok'>OK</span>" ;;
    MED) spf_detail_badge="<span class='badge med'>$spf_reason_label</span>" ;;
    NOK) spf_detail_badge="<span class='badge nok'>$spf_reason_label</span>" ;;
esac

case "$dkim_status" in
    OK) dkim_detail_badge="<span class='badge ok'>OK</span>" ;;
    MED) dkim_detail_badge="<span class='badge med'>MODERATE</span>" ;;
    NOK) dkim_detail_badge="<span class='badge nok'>Not configured</span>" ;;
esac

case "$dmarc_status" in
    OK) dmarc_detail_badge="<span class='badge ok'>reject</span>" ;;
    MED) dmarc_detail_badge="<span class='badge med'>quarantine</span>" ;;
    NOK)
        if [[ "$dmarc_detailled" == *"p=none"* ]]; then
            dmarc_detail_badge="<span class='badge nok'>monitoring only</span>"
        else
            dmarc_detail_badge="<span class='badge nok'>Not configured</span>"
        fi
        ;;
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
.badge.med { background:#fff7db; color:#8a5a00; border:1px solid #ffd66b; }
.muted { color:#2d3748; font-weight:400; }
.label { color:#6b7280; font-size:0.85rem; margin-right:6px; }
.u { text-decoration:underline; color:#374151; }
</style>

<div class="detail-box">
  <div><span class="label">Service: $service</span></div>

  <div class="detail-sub"><span class="u">Major controls:</span></div>
  <div class="tech">
SPF:    $( [ -n "$spf_detailled" ] && echo "$spf_detail_badge <span class='muted'>${spf_detailled}</span>" || echo $spf_detail_badge )
$( [ -n "$dkim_detailled" ] && echo "$dkim_detailled" || echo "DKIM:   <span class='badge nok'>Not configured</span>" )
DMARC:  $( [ -n "$dmarc_detailled" ] && echo "$dmarc_detail_badge <span class='muted'>${dmarc_detailled}</span>" || echo $dmarc_detail_badge )
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
        local spf_reason_label=""
        case "$spf_reason" in
            multiple_records) spf_reason_label="multiple SPF records" ;;
            plus_all) spf_reason_label="+all - accept all senders" ;;
            neutral_all) spf_reason_label="?all - neutral, no protection" ;;
            missing_all) spf_reason_label="missing 'all' mechanism" ;;
            not_configured) spf_reason_label="not configured" ;;
            softfail) spf_reason_label="~all - softfail" ;;
            hardfail) spf_reason_label="-all" ;;
            *) spf_reason_label="invalid configuration" ;;
        esac
        
        local dkim_cell="$dkim_status"
        local dkim_reason_label=""
        case "$dkim_status" in
            OK) dkim_reason_label="RSA >2048 bits" ;;
            MED) dkim_reason_label="RSA <2048 bits" ;;
            NOK) dkim_reason_label="not configured" ;;
        esac
        
        local dmarc_cell="$dmarc_status"

        if [ "$spf_status" = "NOK" ]; then
            spf_cell="❌ NOK ($spf_reason_label - [SPF configuration](https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712))"
        elif [ "$spf_status" = "MED" ]; then
            spf_cell="⚠️ MODERATE ($spf_reason_label - [SPF recommandation](https://help.ovhcloud.com/csm/fr-dns-spf-record?id=kb_article_view&sysparm_article=KB0051712))"
        else
            spf_cell="✅ OK"
        fi
        
        if [ "$dkim_status" = "NOK" ]; then
            dkim_cell="❌ NOK ($dkim_reason_label - [DKIM configuration](https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101))"
        elif [ "$dkim_status" = "MED" ]; then
            dkim_cell="⚠️ MODERATE ($dkim_reason_label - [DKIM recommandation](https://help.ovhcloud.com/csm/fr-dns-zone-dkim?id=kb_article_view&sysparm_article=KB0058101))"
        else
            dkim_cell="✅ OK"
        fi
        
        if [ "$dmarc_status" = "NOK" ]; then
            dmarc_cell="❌ NOK ([DMARC configuration](https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153))"
        elif [ "$dmarc_status" = "MED" ]; then
            dmarc_cell="⚠️ MODERATE ([DMARC recommandation](https://help.ovhcloud.com/csm/fr-dns-zone-dmarc?id=kb_article_view&sysparm_article=KB0059153))"
        else
            dmarc_cell="✅ OK"
        fi

        case $risk_level in
            "LOW") risk_cell="🟢 LOW" ;;
            "MODERATE") risk_cell="🟡 MODERATE" ;;
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

    echo ""

    [ "$verbose" = true ] && echo -e "[DEBUG] Checking domain: $domain${NC}"

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
    # SPF Check
    spf=$(dig "$domain" TXT +short | grep -i "v=spf1")
    spf_count=$(printf "%s\n" "$spf" | grep -ic "v=spf1")
    spf_status="NOK"
    spf_reason="not_configured"

    if [ "$spf_count" -eq 1 ] && [[ "$spf" == *"redirect="* ]]; then
        redirect_domain=$(echo "$spf" | sed -n 's/.*redirect=\([^ ]*\).*/\1/p')
        redirect_domain=${redirect_domain%\"}
        spf=$(dig "$redirect_domain" TXT +short | grep -i "v=spf1" | tr -d '"')
        spf_count=$(printf "%s\n" "$spf" | grep -ic "v=spf1")
    fi

    if [ -n "$spf" ]; then
        if [ "$spf_count" -gt 1 ]; then
            print_result "SPF" "NOK" "$spf" "${RED}(multiple SPF records)${NC}"
            spf_status="NOK"
            spf_reason="multiple_records"
        elif [[ "$spf" =~ \+all ]]; then
            print_result "SPF" "NOK" "$spf" "${RED}(+all - accept ALL expeditors !)${NC}"
            spf_status="NOK"
            spf_reason="plus_all"
        elif [[ "$spf" =~ \?all ]]; then
            print_result "SPF" "NOK" "$spf" "${RED}(?all - neutral, no protection)${NC}"
            spf_status="NOK"
            spf_reason="neutral_all"
        elif [[ "$spf" =~ ~all ]]; then
            print_result "SPF" "MED" "$spf" "${ORANGE}(~all - softfail)${NC}"
            spf_status="MED"
            spf_reason="softfail"
        elif [[ "$spf" =~ -all ]]; then
            print_result "SPF" "OK" "$spf" "${GREEN}(-all)${NC}"
            spf_status="OK"
            spf_reason="hardfail"
        else
            print_result "SPF" "NOK" "$spf" "${RED}(no all mechanism)${NC}"
            spf_status="NOK"
            spf_reason="missing_all"
        fi
    else
        print_result "SPF" "NOK" "${RED}Not configured${NC}" ""
        spf_status="NOK"
        spf_reason="not_configured"
    fi

    # DKIM Check
    dkim_found=false
    dkim_status="NOK"
    dkim_details=""
    dkim_has_weak=false
    dkim_has_bad=false
    pk=""
    
    for selector in "${selectors[@]}"; do
        dkim=$(timeout 1 dig "$selector._domainkey.$domain" TXT +short | grep -i "v=DKIM1")
        if [ -n "$dkim" ]; then
            public_key=$(echo "$dkim" | sed -n 's/.*p=\([^;]*\).*/\1/p' | tr -d '" ')
    
            if [ -n "$public_key" ]; then
                pk=$(echo "$public_key" | base64 -d 2>/dev/null | openssl rsa -inform DER -pubin -noout -text 2>/dev/null | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p')
    
                if [ -n "$pk" ]; then
                    dkim_found=true
    
                    if [ "$pk" -ge 2048 ]; then
                        dkim_details+="DKIM ($selector): <span class='badge ok'>OK</span> - RSA $pk bits"$'\n'
                        print_result "DKIM ($selector)" "OK" "${GREEN}(RSA $pk bits)${NC}" ""
                    elif [ "$pk" -ge 1024 ]; then
                        dkim_has_weak=true
                        dkim_details+="DKIM ($selector): <span class='badge med'>MODERATE</span> - RSA $pk bits - weak"$'\n'
                        print_result "DKIM ($selector)" "MED" "${ORANGE}(RSA $pk bits - weak)${NC}" ""
                    else
                        dkim_has_bad=true
                        dkim_details+="DKIM ($selector): <span class='badge nok'>NOK</span> - RSA $pk bits - too weak"$'\n'
                        print_result "DKIM ($selector)" "NOK" "${RED}(RSA $pk bits - too weak)${NC}" ""
                    fi
                else
                    dkim_details+="DKIM ($selector): INFO - invalid key"$'\n'
                fi
            else
                dkim_details+="DKIM ($selector): INFO - empty/revoked key"$'\n'
            fi
        fi
    done
    
    if [ "$dkim_found" == false ]; then
        print_result "DKIM" "NOK" "${RED}Not configured${NC}" ""
        dkim_status="NOK"
    elif [ "$dkim_has_bad" == true ]; then
        dkim_status="NOK"
    elif [ "$dkim_has_weak" == true ]; then
        dkim_status="MED"
    else
        dkim_status="OK"
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
        print_result "DMARC" "NOK" "${RED}Not configured${NC}" ""
        dmarc_status="NOK"
    fi

    # Additional Security Checks
    echo -e "\n${YELLOW}Additional Security Protocols:${NC}"
    
    # BIMI Check
    bimi=$(dig_with_timeout "default._bimi.$domain" TXT +short 2>/dev/null | grep -i "v=BIMI1")
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
    dnskey=$(dig_with_timeout "$domain" DNSKEY)
    ds=$(dig_with_timeout "$domain" DS)
    if echo "$dnskey" | grep -q '\sDNSKEY\s' && echo "$ds" | grep -q '\sDS\s'; then
        dnssec="OK"
        echo -e "DNSSEC: ${GREEN}✓ Activated${NC}"
    else
        echo -e "DNSSEC: ${RED}✗ Not activated${NC}"
    fi

    append_report "$domain" "$spf_status" "$spf" "$spf_reason" "$dkim_status" "$dkim_details" "$dmarc_status" "$dmarc"
}

generate_html_report() {
    local total_domains=$((low_risk + moderate_risk + high_risk))
    
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
        .risk-moderate { border-left-color: #ffc107; }
        .risk-high { border-left-color: #dc3545; }
        .risk-card h3 { margin: 0 0 10px; font-size: 1.2em; }
        .risk-card .count { font-size: 2em; font-weight: bold; margin: 10px 0; }
        .risk-card .percentage { color: #666; }
        .details-row { display: none; background: #fafafa; }
        .details-cell { padding: 0 20px 15px 20px; }
        .sortable { cursor: pointer; user-select: none; }
        .sortable:hover { background: #eef6ff; }
        tr.clickable:hover { background: #eef6ff; cursor: pointer; }
        pre { margin: 0; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #495057; }
        tr:hover { background: #f8f9fa; }
        .badge.med { background:#fff7db; color:#8a5a00; border:1px solid #ffd66b; }
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
                <div class="risk-card risk-moderate">
                    <h3>🟡 Moderate Risk</h3>
                    <div class="count">$moderate_risk</div>
                    <div class="percentage">$([ $total_domains -gt 0 ] && echo "$((moderate_risk * 100 / total_domains))%" || echo "0%")</div>
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
                        <th class="sortable" title="Click to sort">Domain</th>
                        <th class="sortable" title="Click to sort">SPF</th>
                        <th class="sortable" title="Click to sort">DKIM</th>
                        <th class="sortable" title="Click to sort">DMARC</th>
                        <th class="sortable" title="Click to sort">Risk Level</th>
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
        const detailsRow = row.nextElementSibling;
        if (detailsRow && detailsRow.classList.contains("details-row")) {
          detailsRow.style.display =
            detailsRow.style.display === "table-row" ? "none" : "table-row";
        }
      }

      document.querySelectorAll("th").forEach((header, columnIndex) => {
        let ascending = true;

        header.style.cursor = "pointer";

        header.addEventListener("click", () => {
          const tableBody = header.closest("table").querySelector("tbody");

          const rowPairs = Array.from(
            tableBody.querySelectorAll("tr.clickable"),
          ).map((domainRow) => ({
            domainRow,
            detailsRow: domainRow.nextElementSibling,
          }));

          rowPairs.sort((first, second) => {
            const firstValue =
              first.domainRow.cells[columnIndex].innerText.trim();
            const secondValue =
              second.domainRow.cells[columnIndex].innerText.trim();

            if (columnIndex >= 1 && columnIndex <= 3) {
              const statusOrder = {
                OK: 1,
                MODERATE: 2,
                NOK: 3,
              };

              const firstStatus = firstValue.includes(" OK")
                ? "OK"
                : firstValue.includes("MODERATE")
                  ? "MODERATE"
                  : "NOK";

              const secondStatus = secondValue.includes(" OK")
                ? "OK"
                : secondValue.includes("MODERATE")
                  ? "MODERATE"
                  : "NOK";

              return ascending
                ? statusOrder[firstStatus] - statusOrder[secondStatus]
                : statusOrder[secondStatus] - statusOrder[firstStatus];
            }

            if (columnIndex === 4) {
              const riskOrder = {
                LOW: 1,
                MODERATE: 2,
                HIGH: 3,
              };

              const firstRisk = firstValue.includes("LOW")
                ? "LOW"
                : firstValue.includes("MODERATE")
                  ? "MODERATE"
                  : "HIGH";

              const secondRisk = secondValue.includes("LOW")
                ? "LOW"
                : secondValue.includes("MODERATE")
                  ? "MODERATE"
                  : "HIGH";

              return ascending
                ? riskOrder[firstRisk] - riskOrder[secondRisk]
                : riskOrder[secondRisk] - riskOrder[firstRisk];
            }

            return ascending
              ? firstValue.localeCompare(secondValue, undefined, {
                  numeric: true,
                })
              : secondValue.localeCompare(firstValue, undefined, {
                  numeric: true,
                });
          });

          ascending = !ascending;

          rowPairs.forEach((pair) => {
            tableBody.appendChild(pair.domainRow);
            tableBody.appendChild(pair.detailsRow);
          });
        });
      });
    </script>
</body>
</html>
EOF
}

generate_markdown_report() {
    local total_domains=$((low_risk + moderate_risk + high_risk))
    
    cat << EOF
# Mailynx Report

## Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| 🟢 LOW | $low_risk | $([ $total_domains -gt 0 ] && echo "$((low_risk * 100 / total_domains))%" || echo "0%") |
| 🟡 MODERATE | $moderate_risk | $([ $total_domains -gt 0 ] && echo "$((moderate_risk * 100 / total_domains))%" || echo "0%") |
| 🔴 HIGH | $high_risk | $([ $total_domains -gt 0 ] && echo "$((high_risk * 100 / total_domains))%" || echo "0%") |

**Total domains analyzed:** $total_domains

## Detailed Results

| Domain | SPF | DKIM | DMARC | Risk Level |
|--------|-----|------|-------|------------|
$domains_table

---
*Generated by [Mailynx](https://github.com/Elymaro/mailynx) - Mail DNS Records Audit Tool*
EOF
}

generate_csv_report() {

cat << EOF
Domain,Service,SPF,DKIM,DMARC,Risk Level
$csv_table
EOF
}

# Initialize domains table
domains_table=""
csv_table=""

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

# Generate and save reports
if [ -n "$output_file" ]; then
    output_base="${output_file%.*}"
else
    output_base="mailynx_output"
fi

if [ "$html_output" = true ]; then
    generate_html_report > "${output_base}.html"
    echo -e "${GREEN}HTML report saved to ${output_base}.html${NC}"
elif [ -n "$output_file" ]; then
    generate_markdown_report > "${output_base}.md"
    echo -e "${GREEN}Markdown report saved to ${output_base}.md${NC}"
fi

generate_csv_report > "${output_base}.csv"
echo -e "${GREEN}CSV report saved to ${output_base}.csv${NC}"