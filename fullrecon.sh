#!/bin/bash
##################################################
# 🐛 FULL BUG BOUNTY RECON SCRIPT — FIXED & ENHANCED
# Usage: ./fullrecon.sh <domain> [options]
# Options:
#   --quick        Skip slow steps (nuclei, port scan)
#   --deep         Enable deep crawling + arjun param discovery
#   --ports        Enable full port scan
#   --notify       Enable desktop notifications (macOS)
##################################################

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[+]${NC} $(date '+%H:%M:%S') $1"; }
info()    { echo -e "${CYAN}[*]${NC} $(date '+%H:%M:%S') $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $(date '+%H:%M:%S') $1"; }
section() { echo -e "\n${MAGENTA}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  $1\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
timer()   { echo -e "${YELLOW}  ⏱  Phase time: $(( SECONDS - PHASE_START ))s${NC}"; }
notify()  { [[ "$NOTIFY" == "true" ]] && osascript -e "display notification \"$1\" with title \"Recon: $domain\"" 2>/dev/null || true; }
cmd_ok()  { command -v "$1" &>/dev/null; }

# ── helpers for HTML escaping & file-to-HTML-rows ──────────────────────────
htmlesc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }

# Emit <li> rows from a file (max N lines). Usage: file_rows FILE MAX
file_rows() {
  local f="$1" max="${2:-200}"
  if [ -s "$f" ]; then
    head -"$max" "$f" | htmlesc | while IFS= read -r line; do
      echo "      <li>${line}</li>"
    done
    local total
    total=$(wc -l < "$f" | tr -d ' ')
    if [ "$total" -gt "$max" ]; then
      echo "      <li class='more'>… and $(( total - max )) more lines (see file)</li>"
    fi
  else
    echo "      <li class='empty'>— no data —</li>"
  fi
}

# Count lines safely
cnt() { [ -s "$1" ] && wc -l < "$1" | tr -d ' ' || echo "0"; }

TOTAL_START=$SECONDS
QUICK=false; DEEP=false; PORTS=false; NOTIFY=false; domain=""

for arg in "$@"; do
  case $arg in
    --quick)  QUICK=true ;;
    --deep)   DEEP=true  ;;
    --ports)  PORTS=true ;;
    --notify) NOTIFY=true ;;
    --*)      warn "Unknown flag: $arg" ;;
    *)        [[ -z "$domain" ]] && domain="$arg" ;;
  esac
done

if [ -z "$domain" ]; then
  echo -e "${RED}Usage:${NC} ./fullrecon.sh <domain> [--quick] [--deep] [--ports] [--notify]"
  exit 1
fi

BASE=~/recon/$domain
mkdir -p $BASE/{subdomains,hosts,urls,params,js,secrets,dns,ports,vulns,takeover,tech,reports,screenshots}
cd $BASE
LOG_FILE="$BASE/reports/recon.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗"
echo -e "║   🐛 FULL RECON: $(printf '%-35s' $domain)║"
echo -e "╚══════════════════════════════════════════════════╝${NC}"
echo -e "  Mode: $([ $QUICK = true ] && echo 'QUICK' || echo 'FULL') | Deep: $DEEP | Ports: $PORTS | Notify: $NOTIFY"
echo -e "  Output: $BASE\n"

##################################################
# PHASE 1 — SUBDOMAIN ENUMERATION
##################################################
section "PHASE 1 — Subdomain Enumeration"
PHASE_START=$SECONDS

log "subfinder..."
cmd_ok subfinder && subfinder -d $domain -silent 2>/dev/null > subdomains/subfinder.txt || touch subdomains/subfinder.txt

log "assetfinder..."
cmd_ok assetfinder && assetfinder --subs-only $domain 2>/dev/null > subdomains/assetfinder.txt || touch subdomains/assetfinder.txt

log "crt.sh passive..."
curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' | sort -u > subdomains/crtsh.txt || touch subdomains/crtsh.txt

log "RapidDNS passive..."
curl -s "https://rapiddns.io/subdomain/$domain?full=1" 2>/dev/null \
  | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > subdomains/rapiddns.txt || touch subdomains/rapiddns.txt

log "AlienVault OTX passive..."
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" 2>/dev/null \
  | jq -r '.passive_dns[].hostname' 2>/dev/null \
  | grep -E "\.$domain$" | sort -u > subdomains/otx.txt || touch subdomains/otx.txt

log "Wayback subdomain harvest..."
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=text&fl=original&collapse=urlkey" 2>/dev/null \
  | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > subdomains/wayback_subs.txt || touch subdomains/wayback_subs.txt

log "Combining & deduplicating subdomains..."
cat subdomains/*.txt | sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' \
  | grep -E "^[a-zA-Z0-9._-]+\.[a-z]{2,}$" | sort -u > subdomains/all_subs.txt

TOTAL_SUBS=$(cnt subdomains/all_subs.txt)
log "Total unique subdomains: ${BOLD}$TOTAL_SUBS${NC}"
timer; notify "Phase 1 done — $TOTAL_SUBS subdomains"

##################################################
# PHASE 2 — DNS RECON
##################################################
section "PHASE 2 — DNS Recon"
PHASE_START=$SECONDS

if cmd_ok dnsx; then
  log "DNS A/CNAME/MX/TXT/NS records via dnsx..."
  dnsx -l subdomains/all_subs.txt -silent -a -cname -mx -ns -txt -resp \
    -o dns/dns_records.txt 2>/dev/null || true
  dnsx -l subdomains/all_subs.txt -silent -a -resp-only \
    -o dns/resolved_ips.txt 2>/dev/null || true
else
  warn "dnsx not found, skipping DNS recon"
  touch dns/dns_records.txt dns/resolved_ips.txt
fi

log "SPF / DMARC / MX / Zone Transfer checks..."
{
  echo "=== SPF ==="
  dig +short TXT $domain 2>/dev/null | grep "v=spf" || echo "No SPF found — possible email spoofing!"
  echo "=== DMARC ==="
  dig +short TXT _dmarc.$domain 2>/dev/null || echo "No DMARC found — possible email spoofing!"
  echo "=== MX ==="
  dig +short MX $domain 2>/dev/null || echo "No MX records"
  echo "=== NS ==="
  dig +short NS $domain 2>/dev/null
  echo "=== Zone Transfer Attempt ==="
  for ns in $(dig +short NS $domain 2>/dev/null); do
    dig axfr $domain @$ns 2>/dev/null | head -30 || echo "Zone transfer refused on $ns"
  done
} > dns/email_security.txt

log "Checking for dangling DNS (NXDOMAIN CNAMEs)..."
if cmd_ok dnsx; then
  dnsx -l subdomains/all_subs.txt -silent -cname -resp 2>/dev/null \
    | grep "NXDOMAIN\|no such host" > dns/dangling_cnames.txt || touch dns/dangling_cnames.txt
fi

timer

##################################################
# PHASE 3 — ALIVE HOST PROBING
##################################################
section "PHASE 3 — Alive Host Probing"
PHASE_START=$SECONDS

if cmd_ok httpx; then
  log "Probing with httpx..."
  cat subdomains/all_subs.txt | httpx \
    -silent -title -status-code -tech-detect \
    -server -ip -cdn -location -follow-redirects \
    -threads 50 -timeout 10 \
    -o hosts/alive_full.txt 2>/dev/null || true
  awk '{print $1}' hosts/alive_full.txt | sort -u > hosts/alive_urls.txt
else
  warn "httpx not found"; touch hosts/alive_full.txt hosts/alive_urls.txt
fi

ALIVE=$(cnt hosts/alive_urls.txt)
log "Alive hosts: ${BOLD}$ALIVE${NC}"

grep " 200 " hosts/alive_full.txt | awk '{print $1}' > hosts/status_200.txt  || touch hosts/status_200.txt
grep " 403 " hosts/alive_full.txt | awk '{print $1}' > hosts/status_403.txt  || touch hosts/status_403.txt
grep " 401 " hosts/alive_full.txt | awk '{print $1}' > hosts/status_401.txt  || touch hosts/status_401.txt
grep -E " 30[12] " hosts/alive_full.txt | awk '{print $1}' > hosts/redirects.txt || touch hosts/redirects.txt

log "Interesting hosts (admin, dev, staging, api, internal)..."
grep -iE "(admin|dev|staging|test|internal|api|vpn|mail|remote|jenkins|gitlab|jira|grafana|kibana|consul)" \
  hosts/alive_urls.txt > hosts/interesting.txt 2>/dev/null || touch hosts/interesting.txt
INTERESTING=$(cnt hosts/interesting.txt)
[ "$INTERESTING" -gt 0 ] && warn "⚠️  $INTERESTING interesting hosts → hosts/interesting.txt"

timer; notify "Phase 3 done — $ALIVE alive"

##################################################
# PHASE 4 — PORT SCANNING
##################################################
if [ "$QUICK" = false ] || [ "$PORTS" = true ]; then
  section "PHASE 4 — Port Scanning"
  PHASE_START=$SECONDS
  if cmd_ok naabu; then
    PORT_OPT="-top-ports 1000"
    [ "$PORTS" = true ] && PORT_OPT="-p -"
    naabu -l hosts/alive_urls.txt $PORT_OPT -silent \
      -o ports/open_ports.txt 2>/dev/null || touch ports/open_ports.txt
    log "Open port entries: $(cnt ports/open_ports.txt)"
    grep -E ":(22|23|25|110|143|3306|5432|6379|27017|9200|5601|8080|8443|9090|3000|4848|7001|8888)$" \
      ports/open_ports.txt > ports/interesting_ports.txt 2>/dev/null || touch ports/interesting_ports.txt
    [ -s ports/interesting_ports.txt ] && warn "⚠️  Interesting ports → ports/interesting_ports.txt"
  else
    warn "naabu not found — falling back to nmap..."
    touch ports/open_ports.txt ports/interesting_ports.txt
    cmd_ok nmap && nmap -iL hosts/alive_urls.txt --top-ports 100 -T4 \
      -oN ports/nmap_scan.txt 2>/dev/null || warn "nmap not found either"
  fi
  timer
else
  touch ports/open_ports.txt ports/interesting_ports.txt
fi

##################################################
# PHASE 5 — SUBDOMAIN TAKEOVER
##################################################
section "PHASE 5 — Subdomain Takeover Check"
PHASE_START=$SECONDS

if cmd_ok subjack; then
  FP=""; [ -f ~/tools/fingerprints.json ] && FP="-c ~/tools/fingerprints.json"
  subjack -w subdomains/all_subs.txt $FP -t 50 -timeout 30 \
    -o takeover/vulnerable.txt -ssl 2>/dev/null || true
  TAKEOVER=$(cnt takeover/vulnerable.txt)
  [ "$TAKEOVER" -gt 0 ] \
    && warn "⚠️  Potential takeovers: $TAKEOVER → takeover/vulnerable.txt" \
    || log "No obvious takeovers"
else
  warn "subjack not found"; touch takeover/vulnerable.txt
fi

if cmd_ok dnsx; then
  SERVICES="github.io|heroku|amazonaws|netlify|pages.dev|surge.sh|fastly|shopify|statuspage|zendesk|ghost.io|webflow"
  grep -iE "$SERVICES" dns/dns_records.txt 2>/dev/null > takeover/cname_third_party.txt || touch takeover/cname_third_party.txt
  [ -s takeover/cname_third_party.txt ] && warn "⚠️  3rd-party CNAMEs → takeover/cname_third_party.txt"
else
  touch takeover/cname_third_party.txt
fi
timer

##################################################
# PHASE 6 — URL COLLECTION
##################################################
section "PHASE 6 — URL Collection"
PHASE_START=$SECONDS

log "GAU (historical)..."
cmd_ok gau && cat subdomains/all_subs.txt | gau --threads 5 \
  --blacklist ttf,woff,svg,png,jpg,jpeg,gif,css,ico,woff2 \
  2>/dev/null > urls/gau.txt || touch urls/gau.txt

log "Wayback URLs..."
cmd_ok waybackurls && cat subdomains/all_subs.txt | waybackurls 2>/dev/null \
  > urls/wayback.txt || touch urls/wayback.txt

log "Katana crawler..."
if cmd_ok katana; then
  DEPTH=2; [ "$DEEP" = true ] && DEPTH=5
  katana -list hosts/alive_urls.txt -silent -depth $DEPTH \
    -jc -kf all -o urls/katana.txt 2>/dev/null || touch urls/katana.txt
else
  touch urls/katana.txt
fi

log "Combining all URLs..."
cat urls/gau.txt urls/wayback.txt urls/katana.txt 2>/dev/null \
  | grep -E "^https?://" | grep "$domain" \
  | sort -u > urls/all_urls.txt

TOTAL_URLS=$(cnt urls/all_urls.txt)
log "Total unique URLs: ${BOLD}$TOTAL_URLS${NC}"
timer; notify "Phase 6 done — $TOTAL_URLS URLs"

##################################################
# PHASE 7 — PARAMETER EXTRACTION & CLASSIFICATION
##################################################
section "PHASE 7 — Parameter Extraction"
PHASE_START=$SECONDS

grep "=" urls/all_urls.txt | sort -u > params/all_params.txt
TOTAL_PARAMS=$(cnt params/all_params.txt)
log "Total URLs with params: $TOTAL_PARAMS"

grep -iE "[?&](q|s|search|query|keyword|term|input|text|message|comment|title|name|value|data|content|html|output|return|redirect|url|next|ref|src|source|dest|destination|callback|jsonp|page|view|template)=" \
  params/all_params.txt | sort -u > params/xss_candidates.txt
grep -iE "[?&](id|user_id|item|product|order|cat|category|page|sort|filter|offset|limit|select|from|where|group|having|union|table|column|field|record|num|number|index|row|col|set|update|insert|delete|query|search|keyword|start|end|type|ref)=" \
  params/all_params.txt | sort -u > params/sqli_candidates.txt
grep -iE "[?&](url|redirect|redir|return|next|goto|dest|destination|target|link|out|ref|location|forward|continue|path|uri|returnTo|returnUrl|back|from|to|source|site|page)=" \
  params/all_params.txt | sort -u > params/open_redirect_candidates.txt
grep -iE "[?&](url|uri|path|src|source|dest|host|server|domain|endpoint|proxy|load|fetch|file|doc|document|page|feed|api|resource|img|image|link|href|action|data|request)=" \
  params/all_params.txt | sort -u > params/ssrf_candidates.txt
grep -iE "[?&](file|path|dir|folder|include|page|doc|template|lang|locale|view|module|config|layout|prefix|suffix|root|base)=" \
  params/all_params.txt | sort -u > params/lfi_candidates.txt

log "XSS:$(cnt params/xss_candidates.txt) SQLi:$(cnt params/sqli_candidates.txt) Redirect:$(cnt params/open_redirect_candidates.txt) SSRF:$(cnt params/ssrf_candidates.txt) LFI:$(cnt params/lfi_candidates.txt)"

if [ "$DEEP" = true ] && cmd_ok arjun; then
  log "Arjun hidden param discovery (deep)..."
  while IFS= read -r url; do
    arjun -u "$url" --stable -q 2>/dev/null >> params/arjun_hidden.txt || true
  done < <(head -50 hosts/status_200.txt)
fi
touch params/arjun_hidden.txt
timer

##################################################
# PHASE 8 — JS FILE ANALYSIS
##################################################
section "PHASE 8 — JavaScript Analysis"
PHASE_START=$SECONDS

cat urls/all_urls.txt | grep -iE "\.js(\?|$)" | sort -u > js/js_urls.txt
cmd_ok hakrawler && cat hosts/alive_urls.txt | hakrawler -subs 2>/dev/null \
  | grep -iE "\.js(\?|$)" >> js/js_urls.txt || true
cmd_ok subjs && cat hosts/alive_urls.txt | subjs 2>/dev/null \
  | grep -iE "\.js(\?|$)" >> js/js_urls.txt || true
sort -u js/js_urls.txt -o js/js_urls.txt

JS_COUNT=$(cnt js/js_urls.txt)
log "Total JS files: $JS_COUNT"

log "Hunting secrets in JS files..."
SECRET_PATTERNS='(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token|bearer|password|passwd|private[_-]?key|aws[_-]?access|aws[_-]?secret|AKIA[0-9A-Z]{16}|s3\.amazonaws\.com|-----BEGIN (RSA|EC|OPENSSH)|eyJ[a-zA-Z0-9_-]{10,}\.eyJ|mongodb\+srv|postgres://|mysql://|redis://|smtp\.|SLACK_|STRIPE_|TWILIO_|SENDGRID_|FIREBASE|GITHUB_TOKEN|npm_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10,})'
touch secrets/js_secrets.txt
while IFS= read -r js_url; do
  OUT=$(curl -sk --max-time 10 "$js_url" 2>/dev/null \
    | grep -oiE "$SECRET_PATTERNS" | sort -u)
  if [ -n "$OUT" ]; then
    echo "=== $js_url ===" >> secrets/js_secrets.txt
    echo "$OUT"           >> secrets/js_secrets.txt
    echo ""               >> secrets/js_secrets.txt
  fi
done < js/js_urls.txt

SECRET_COUNT=$(grep -c "^===" secrets/js_secrets.txt 2>/dev/null || echo 0)
[ "$SECRET_COUNT" -gt 0 ] \
  && warn "⚠️  Secrets in $SECRET_COUNT JS files → secrets/js_secrets.txt" \
  || log "No obvious secrets found"

log "Extracting JS internal endpoints..."
touch js/endpoints.txt
while IFS= read -r js_url; do
  curl -sk --max-time 10 "$js_url" 2>/dev/null \
    | grep -oiE '("|'"'"')(\/[a-zA-Z0-9_\-\/\.]{3,})("|'"'"')' \
    | tr -d "\"'" \
    | sort -u >> js/endpoints.txt || true
done < js/js_urls.txt
sort -u js/endpoints.txt -o js/endpoints.txt

cmd_ok retire && retire --jspath js/ --outputformat json \
  --outputpath js/retire_report.json 2>/dev/null || true

timer

##################################################
# PHASE 9 — TECHNOLOGY FINGERPRINTING
##################################################
section "PHASE 9 — Technology Fingerprinting"
PHASE_START=$SECONDS

grep -oP '\[([^\]]+)\]' hosts/alive_full.txt 2>/dev/null | tr -d '[]' \
  | sort | uniq -c | sort -rn > tech/tech_summary.txt || touch tech/tech_summary.txt

if cmd_ok wappalyzer; then
  while IFS= read -r url; do
    echo "=== $url ===" >> tech/wappalyzer.txt
    wappalyzer "$url" 2>/dev/null >> tech/wappalyzer.txt || true
  done < <(head -20 hosts/alive_urls.txt)
fi
touch tech/wappalyzer.txt tech/tech_summary.txt
timer

##################################################
# PHASE 10 — VULNERABILITY SCANNING (NUCLEI)
##################################################
touch vulns/nuclei_findings.txt vulns/nuclei_exposure.txt vulns/403_bypass.txt
if [ "$QUICK" = false ]; then
  section "PHASE 10 — Vulnerability Scanning (Nuclei)"
  PHASE_START=$SECONDS
  if cmd_ok nuclei; then
    log "Nuclei — CVE/misconfig/sqli/xss/ssrf/rce..."
    nuclei -l hosts/alive_urls.txt \
      -severity critical,high,medium \
      -tags cve,sqli,xss,ssrf,rce,lfi,redirect,exposure,misconfig,default-login \
      -silent -rate-limit 50 \
      -o vulns/nuclei_findings.txt 2>/dev/null || true
    VULN_COUNT=$(cnt vulns/nuclei_findings.txt)
    [ "$VULN_COUNT" -gt 0 ] \
      && warn "⚠️  Nuclei: $VULN_COUNT findings" \
      || log "No nuclei findings"

    log "Nuclei — exposed files/backups/configs..."
    nuclei -l hosts/alive_urls.txt \
      -tags exposure,files,backup,config \
      -severity info,low,medium,high,critical \
      -silent -rate-limit 30 \
      -o vulns/nuclei_exposure.txt 2>/dev/null || true

    log "Nuclei — 403 bypass check..."
    [ -s hosts/status_403.txt ] && nuclei -l hosts/status_403.txt \
      -tags "403-bypass" -silent -rate-limit 20 \
      -o vulns/403_bypass.txt 2>/dev/null || true
  else
    warn "nuclei not found, skipping"
  fi
  timer; notify "Phase 10 done"
fi

##################################################
# PHASE 11 — SCREENSHOTS (gowitness)
##################################################
if cmd_ok gowitness && [ "$QUICK" = false ]; then
  section "PHASE 11 — Screenshots"
  PHASE_START=$SECONDS
  gowitness file -f hosts/alive_urls.txt \
    --destination screenshots/ \
    --log-level error 2>/dev/null || true
  log "Screenshots saved → screenshots/"
  timer
fi

##################################################
# PHASE 12 — HTML SUMMARY REPORT  (FIX: all data embedded)
##################################################
section "PHASE 12 — Generating Summary Report"
TOTAL_TIME=$(( SECONDS - TOTAL_START ))
REPORT="$BASE/reports/summary.html"
SCAN_DATE=$(date)

# ── collect all counts BEFORE writing HTML ─────────────────────────────────
R_SUBS=$(cnt subdomains/all_subs.txt)
R_ALIVE=$(cnt hosts/alive_urls.txt)
R_URLS=$(cnt urls/all_urls.txt)
R_PARAMS=$(cnt params/all_params.txt)
R_JS=$(cnt js/js_urls.txt)
R_VULNS=$(cnt vulns/nuclei_findings.txt)
R_SECRETS=$( grep -c "^===" secrets/js_secrets.txt 2>/dev/null || echo 0 )
R_TAKEOVER=$(cnt takeover/vulnerable.txt)
R_INTERESTING=$(cnt hosts/interesting.txt)
R_XSS=$(cnt params/xss_candidates.txt)
R_SQLI=$(cnt params/sqli_candidates.txt)
R_REDIR=$(cnt params/open_redirect_candidates.txt)
R_SSRF=$(cnt params/ssrf_candidates.txt)
R_LFI=$(cnt params/lfi_candidates.txt)
R_PORTS=$(cnt ports/open_ports.txt)
R_ENDPOINTS=$(cnt js/endpoints.txt)
R_EXPOSURE=$(cnt vulns/nuclei_exposure.txt)
R_403=$(cnt vulns/403_bypass.txt)

# ── badge color helper ──────────────────────────────────────────────────────
badge_color() { [ "$1" -gt 0 ] && echo "red" || echo "green"; }

# ── pre-render all data sections (avoids heredoc subshell issues) ───────────
ROWS_SUBS=$(file_rows subdomains/all_subs.txt 300)
ROWS_ALIVE=$(file_rows hosts/alive_full.txt 200)
ROWS_INTERESTING=$(file_rows hosts/interesting.txt 100)
ROWS_DNS=$(file_rows dns/dns_records.txt 200)
ROWS_EMAIL=$(file_rows dns/email_security.txt 50)
ROWS_DANGLING=$(file_rows dns/dangling_cnames.txt 100)
ROWS_PORTS=$(file_rows ports/open_ports.txt 200)
ROWS_IPORTS=$(file_rows ports/interesting_ports.txt 100)
ROWS_TAKEOVER=$(file_rows takeover/vulnerable.txt 100)
ROWS_CNAME3P=$(file_rows takeover/cname_third_party.txt 100)
ROWS_URLS=$(file_rows urls/all_urls.txt 300)
ROWS_XSS=$(file_rows params/xss_candidates.txt 200)
ROWS_SQLI=$(file_rows params/sqli_candidates.txt 200)
ROWS_REDIR=$(file_rows params/open_redirect_candidates.txt 200)
ROWS_SSRF=$(file_rows params/ssrf_candidates.txt 200)
ROWS_LFI=$(file_rows params/lfi_candidates.txt 200)
ROWS_ARJUN=$(file_rows params/arjun_hidden.txt 100)
ROWS_JS=$(file_rows js/js_urls.txt 200)
ROWS_ENDPOINTS=$(file_rows js/endpoints.txt 200)
ROWS_SECRETS=$(file_rows secrets/js_secrets.txt 300)
ROWS_TECH=$(file_rows tech/tech_summary.txt 100)
ROWS_VULNS=$(file_rows vulns/nuclei_findings.txt 300)
ROWS_EXPOSURE=$(file_rows vulns/nuclei_exposure.txt 200)
ROWS_403=$(file_rows vulns/403_bypass.txt 100)

# ── write HTML using printf (no heredoc subshell issues) ───────────────────
{
printf '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n'
printf '<title>Recon Report — %s</title>\n' "$domain"
cat << 'STYLE'
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0d1117;--card:#161b22;--card2:#1c2128;--border:#30363d;--accent:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149;--text:#c9d1d9;--muted:#8b949e;--purple:#bc8cff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:1.5rem;font-size:14px}
a{color:var(--accent)}
h1{color:var(--accent);font-size:1.6rem;margin-bottom:.2rem}
.meta{color:var(--muted);font-size:.8rem;margin-bottom:1.5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:.8rem;margin-bottom:1.5rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem}
.card .label{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.3rem}
.card .value{font-size:1.9rem;font-weight:bold}
.green{color:var(--green)}.yellow{color:var(--yellow)}.red{color:var(--red)}.blue{color:var(--accent)}.purple{color:var(--purple)}
.tabs{display:flex;flex-wrap:wrap;gap:.4rem;margin-bottom:1rem}
.tab{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.35rem .8rem;cursor:pointer;font-size:.8rem;color:var(--muted);transition:all .2s}
.tab:hover,.tab.active{background:var(--accent);color:#000;border-color:var(--accent)}
.panel{display:none}.panel.active{display:block}
.section{background:var(--card);border:1px solid var(--border);border-radius:8px;margin-bottom:1rem;overflow:hidden}
.section h2{padding:.6rem 1rem;border-bottom:1px solid var(--border);font-size:.85rem;color:var(--accent);display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none}
.section h2:hover{background:var(--card2)}
.section-body{max-height:400px;overflow-y:auto}
.section ul{list-style:none;padding:.5rem}
.section ul li{padding:.2rem .5rem;font-size:.78rem;border-bottom:1px solid #21262d;word-break:break-all;line-height:1.5}
.section ul li:last-child{border-bottom:none}
.section ul li.empty{color:var(--muted);font-style:italic}
.section ul li.more{color:var(--yellow);font-style:italic}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:.7rem;font-weight:bold;margin-left:.4rem}
.badge.red{background:#3d1a1a;color:var(--red)}
.badge.yellow{background:#2d2204;color:var(--yellow)}
.badge.green{background:#0d2818;color:var(--green)}
.badge.blue{background:#0c2a4a;color:var(--accent)}
.collapsed .section-body{display:none}
.search-box{width:100%;padding:.5rem;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:.8rem;margin-bottom:.8rem}
.search-box:focus{outline:none;border-color:var(--accent)}
footer{text-align:center;color:var(--muted);font-size:.75rem;margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border)}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
STYLE

printf '<script>\n'
cat << 'SCRIPT'
function showTab(id){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('panel-'+id).classList.add('active');
  document.querySelector('[data-tab="'+id+'"]').classList.add('active');
}
function toggleSection(el){
  el.closest('.section').classList.toggle('collapsed');
}
function filterList(input,listId){
  var q=input.value.toLowerCase();
  document.querySelectorAll('#'+listId+' li').forEach(function(li){
    li.style.display=li.textContent.toLowerCase().includes(q)?'':'none';
  });
}
window.onload=function(){showTab('overview')};
SCRIPT
printf '</script>\n</head>\n<body>\n'

printf '<h1>🐛 Recon Report: %s</h1>\n' "$domain"
printf '<p class="meta">Generated: %s &nbsp;|&nbsp; Total time: %ss &nbsp;|&nbsp; Mode: %s | Deep: %s | Ports: %s</p>\n' \
  "$SCAN_DATE" "$TOTAL_TIME" "$([ $QUICK = true ] && echo QUICK || echo FULL)" "$DEEP" "$PORTS"

# ── stat cards ──────────────────────────────────────────────────────────────
printf '<div class="grid">\n'
printf '  <div class="card"><div class="label">Subdomains</div><div class="value blue">%s</div></div>\n' "$R_SUBS"
printf '  <div class="card"><div class="label">Alive Hosts</div><div class="value green">%s</div></div>\n' "$R_ALIVE"
printf '  <div class="card"><div class="label">Total URLs</div><div class="value blue">%s</div></div>\n' "$R_URLS"
printf '  <div class="card"><div class="label">Parameters</div><div class="value yellow">%s</div></div>\n' "$R_PARAMS"
printf '  <div class="card"><div class="label">JS Files</div><div class="value purple">%s</div></div>\n' "$R_JS"
printf '  <div class="card"><div class="label">JS Endpoints</div><div class="value purple">%s</div></div>\n' "$R_ENDPOINTS"
printf '  <div class="card"><div class="label">Nuclei Findings</div><div class="value %s">%s</div></div>\n' "$(badge_color $R_VULNS)" "$R_VULNS"
printf '  <div class="card"><div class="label">JS Secrets</div><div class="value %s">%s</div></div>\n' "$(badge_color $R_SECRETS)" "$R_SECRETS"
printf '  <div class="card"><div class="label">Takeover Risk</div><div class="value %s">%s</div></div>\n' "$(badge_color $R_TAKEOVER)" "$R_TAKEOVER"
printf '  <div class="card"><div class="label">Open Ports</div><div class="value yellow">%s</div></div>\n' "$R_PORTS"
printf '  <div class="card"><div class="label">Exposure Findings</div><div class="value %s">%s</div></div>\n' "$(badge_color $R_EXPOSURE)" "$R_EXPOSURE"
printf '  <div class="card"><div class="label">403 Bypass</div><div class="value %s">%s</div></div>\n' "$(badge_color $R_403)" "$R_403"
printf '</div>\n'

# ── tab navigation ───────────────────────────────────────────────────────────
printf '<div class="tabs">\n'
for t in "overview:📊 Overview" "subdomains:🌐 Subdomains" "hosts:🖥 Hosts" "dns:🔍 DNS" "ports:🔌 Ports" "takeover:💀 Takeover" "urls:🔗 URLs" "params:🎯 Params" "js:⚙️ JavaScript" "vulns:🚨 Vulns" "tech:🛠 Tech"; do
  id="${t%%:*}"; label="${t#*:}"
  printf '  <span class="tab" data-tab="%s" onclick="showTab('"'"'%s'"'"')">%s</span>\n' "$id" "$id" "$label"
done
printf '</div>\n'

# ── OVERVIEW panel ───────────────────────────────────────────────────────────
printf '<div id="panel-overview" class="panel">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🎯 Attack Surface Summary</h2><div class="section-body"><ul>\n'
printf '    <li>XSS Candidates <span class="badge yellow">%s</span></li>\n' "$R_XSS"
printf '    <li>SQLi Candidates <span class="badge yellow">%s</span></li>\n' "$R_SQLI"
printf '    <li>Open Redirect Candidates <span class="badge yellow">%s</span></li>\n' "$R_REDIR"
printf '    <li>SSRF Candidates <span class="badge yellow">%s</span></li>\n' "$R_SSRF"
printf '    <li>LFI Candidates <span class="badge yellow">%s</span></li>\n' "$R_LFI"
printf '    <li>Interesting Hosts (admin/dev/api) <span class="badge %s">%s</span></li>\n' "$(badge_color $R_INTERESTING)" "$R_INTERESTING"
printf '    <li>Nuclei Vulnerability Findings <span class="badge %s">%s</span></li>\n' "$(badge_color $R_VULNS)" "$R_VULNS"
printf '    <li>Exposed Files / Backups <span class="badge %s">%s</span></li>\n' "$(badge_color $R_EXPOSURE)" "$R_EXPOSURE"
printf '    <li>403 Bypass Found <span class="badge %s">%s</span></li>\n' "$(badge_color $R_403)" "$R_403"
printf '    <li>JS Secret Leaks <span class="badge %s">%s</span></li>\n' "$(badge_color $R_SECRETS)" "$R_SECRETS"
printf '    <li>Subdomain Takeover Risk <span class="badge %s">%s</span></li>\n' "$(badge_color $R_TAKEOVER)" "$R_TAKEOVER"
printf '  </ul></div></div>\n'

printf '  <div class="section"><h2 onclick="toggleSection(this)">⭐ Interesting Hosts <span class="badge %s">%s</span></h2><div class="section-body"><ul id="list-interesting">\n' "$(badge_color $R_INTERESTING)" "$R_INTERESTING"
printf '%s\n' "$ROWS_INTERESTING"
printf '  </ul></div></div>\n</div>\n'

# ── SUBDOMAINS panel ─────────────────────────────────────────────────────────
printf '<div id="panel-subdomains" class="panel">\n'
printf '  <input class="search-box" placeholder="Filter subdomains..." oninput="filterList(this,'"'"'list-subs'"'"')">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🌐 All Subdomains <span class="badge blue">%s</span></h2><div class="section-body"><ul id="list-subs">\n' "$R_SUBS"
printf '%s\n' "$ROWS_SUBS"
printf '  </ul></div></div>\n</div>\n'

# ── HOSTS panel ──────────────────────────────────────────────────────────────
printf '<div id="panel-hosts" class="panel">\n'
printf '  <input class="search-box" placeholder="Filter hosts..." oninput="filterList(this,'"'"'list-hosts'"'"')">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🖥 Alive Hosts (full detail) <span class="badge green">%s</span></h2><div class="section-body"><ul id="list-hosts">\n' "$R_ALIVE"
printf '%s\n' "$ROWS_ALIVE"
printf '  </ul></div></div>\n</div>\n'

# ── DNS panel ────────────────────────────────────────────────────────────────
printf '<div id="panel-dns" class="panel">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">📋 DNS Records <span class="badge blue">%s</span></h2><div class="section-body"><ul>\n' "$(cnt dns/dns_records.txt)"
printf '%s\n' "$ROWS_DNS"
printf '  </ul></div></div>\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">📧 Email Security (SPF/DMARC/MX)</h2><div class="section-body"><ul>\n'
printf '%s\n' "$ROWS_EMAIL"
printf '  </ul></div></div>\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">⚠️ Dangling CNAMEs <span class="badge %s">%s</span></h2><div class="section-body"><ul>\n' "$(badge_color $(cnt dns/dangling_cnames.txt))" "$(cnt dns/dangling_cnames.txt)"
printf '%s\n' "$ROWS_DANGLING"
printf '  </ul></div></div>\n</div>\n'

# ── PORTS panel ──────────────────────────────────────────────────────────────
printf '<div id="panel-ports" class="panel">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🔌 Open Ports <span class="badge yellow">%s</span></h2><div class="section-body"><ul>\n' "$R_PORTS"
printf '%s\n' "$ROWS_PORTS"
printf '  </ul></div></div>\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🚨 Interesting Ports <span class="badge %s">%s</span></h2><div class="section-body"><ul>\n' "$(badge_color $(cnt ports/interesting_ports.txt))" "$(cnt ports/interesting_ports.txt)"
printf '%s\n' "$ROWS_IPORTS"
printf '  </ul></div></div>\n</div>\n'

# ── TAKEOVER panel ───────────────────────────────────────────────────────────
printf '<div id="panel-takeover" class="panel">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">💀 Subjack Results <span class="badge %s">%s</span></h2><div class="section-body"><ul>\n' "$(badge_color $R_TAKEOVER)" "$R_TAKEOVER"
printf '%s\n' "$ROWS_TAKEOVER"
printf '  </ul></div></div>\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🔗 3rd-Party CNAME Services <span class="badge %s">%s</span></h2><div class="section-body"><ul>\n' "$(badge_color $(cnt takeover/cname_third_party.txt))" "$(cnt takeover/cname_third_party.txt)"
printf '%s\n' "$ROWS_CNAME3P"
printf '  </ul></div></div>\n</div>\n'

# ── URLS panel ───────────────────────────────────────────────────────────────
printf '<div id="panel-urls" class="panel">\n'
printf '  <input class="search-box" placeholder="Filter URLs..." oninput="filterList(this,'"'"'list-urls'"'"')">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🔗 All URLs <span class="badge blue">%s</span></h2><div class="section-body"><ul id="list-urls">\n' "$R_URLS"
printf '%s\n' "$ROWS_URLS"
printf '  </ul></div></div>\n</div>\n'

# ── PARAMS panel ─────────────────────────────────────────────────────────────
printf '<div id="panel-params" class="panel">\n'
printf '  <input class="search-box" placeholder="Filter params..." oninput="filterList(this,'"'"'list-xss'"'"')">\n'
for pset in "xss_candidates:🔴 XSS Candidates:$R_XSS:list-xss" \
            "sqli_candidates:🔴 SQLi Candidates:$R_SQLI:list-sqli" \
            "open_redirect_candidates:🟡 Open Redirect:$R_REDIR:list-redir" \
            "ssrf_candidates:🟡 SSRF Candidates:$R_SSRF:list-ssrf" \
            "lfi_candidates:🟡 LFI Candidates:$R_LFI:list-lfi" \
            "arjun_hidden:🔵 Arjun Hidden Params:$(cnt params/arjun_hidden.txt):list-arjun"; do
  pfile="${pset%%:*}"; rest="${pset#*:}"; plabel="${rest%%:*}"; rest2="${rest#*:}"; pcount="${rest2%%:*}"; plistid="${rest2#*:}"
  printf '  <div class="section"><h2 onclick="toggleSection(this)">%s <span class="badge yellow">%s</span></h2><div class="section-body"><ul id="%s">\n' "$plabel" "$pcount" "$plistid"
  file_rows "params/${pfile}.txt" 200
  printf '  </ul></div></div>\n'
done
printf '</div>\n'

# ── JS panel ─────────────────────────────────────────────────────────────────
printf '<div id="panel-js" class="panel">\n'
printf '  <input class="search-box" placeholder="Filter JS / secrets..." oninput="filterList(this,'"'"'list-js'"'"')">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">⚙️ JS File URLs <span class="badge purple">%s</span></h2><div class="section-body"><ul id="list-js">\n' "$R_JS"
printf '%s\n' "$ROWS_JS"
printf '  </ul></div></div>\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🗺 Extracted Endpoints <span class="badge purple">%s</span></h2><div class="section-body"><ul>\n' "$R_ENDPOINTS"
printf '%s\n' "$ROWS_ENDPOINTS"
printf '  </ul></div></div>\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🔑 JS Secrets / Leaked Keys <span class="badge %s">%s</span></h2><div class="section-body"><ul>\n' "$(badge_color $R_SECRETS)" "$R_SECRETS"
printf '%s\n' "$ROWS_SECRETS"
printf '  </ul></div></div>\n</div>\n'

# ── VULNS panel ──────────────────────────────────────────────────────────────
printf '<div id="panel-vulns" class="panel">\n'
printf '  <input class="search-box" placeholder="Filter findings..." oninput="filterList(this,'"'"'list-vulns'"'"')">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🚨 Nuclei Findings <span class="badge %s">%s</span></h2><div class="section-body"><ul id="list-vulns">\n' "$(badge_color $R_VULNS)" "$R_VULNS"
printf '%s\n' "$ROWS_VULNS"
printf '  </ul></div></div>\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">📂 Exposed Files / Backups <span class="badge %s">%s</span></h2><div class="section-body"><ul>\n' "$(badge_color $R_EXPOSURE)" "$R_EXPOSURE"
printf '%s\n' "$ROWS_EXPOSURE"
printf '  </ul></div></div>\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🚪 403 Bypass <span class="badge %s">%s</span></h2><div class="section-body"><ul>\n' "$(badge_color $R_403)" "$R_403"
printf '%s\n' "$ROWS_403"
printf '  </ul></div></div>\n</div>\n'

# ── TECH panel ───────────────────────────────────────────────────────────────
printf '<div id="panel-tech" class="panel">\n'
printf '  <div class="section"><h2 onclick="toggleSection(this)">🛠 Technology Summary</h2><div class="section-body"><ul>\n'
printf '%s\n' "$ROWS_TECH"
printf '  </ul></div></div>\n</div>\n'

printf '<footer>🐛 Bug Bounty Recon &nbsp;|&nbsp; %s &nbsp;|&nbsp; %s &nbsp;|&nbsp; Total time: %ss</footer>\n' \
  "$domain" "$SCAN_DATE" "$TOTAL_TIME"
printf '</body>\n</html>\n'

} > "$REPORT"

log "✅ HTML report generated → $REPORT"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗"
echo -e "║   ✅  RECON COMPLETE"
echo -e "╠══════════════════════════════════════════════════╣"
echo -e "║  Domain  : $domain"
echo -e "║  Results : ~/recon/$domain"
echo -e "║  Report  : $REPORT"
echo -e "║  Time    : ${TOTAL_TIME}s"
echo -e "╠══════════════════════════════════════════════════╣"
echo -e "║  Subs: $R_SUBS  |  Alive: $R_ALIVE  |  URLs: $R_URLS"
echo -e "║  Vulns: $R_VULNS  |  Secrets: $R_SECRETS  |  Takeover: $R_TAKEOVER"
echo -e "╚══════════════════════════════════════════════════╝${NC}"

notify "Recon done for $domain — ${TOTAL_TIME}s | Vulns:$R_VULNS Secrets:$R_SECRETS"
open "$REPORT" 2>/dev/null || true