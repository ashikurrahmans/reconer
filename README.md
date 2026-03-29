
# 🧭 Reconer Usage Workflow (Step‑by‑Step Guide)

This guide explains **how a user should use Reconer from start to finish** without confusion.

---

# ⚡ Step 1 — Clone the Tool

```bash
git clone https://github.com/yourusername/Reconer.git
cd reconer
```

---

# ⚙️ Step 2 — Give Execute Permission

Make the script executable:

```bash
chmod +x install.sh
./install.sh
```

✅ This allows your system to run the tool as a program.

---

# 📦 Step 3 — Install Required Dependencies (MAC & Kali)

Install required recon tools:

```bash
Mac Version : 

brew install jq curl httpx subfinder assetfinder gau waybackurls ffuf
npm install -g wappalyzer

Kali Version : 

sudo apt update && sudo apt install -y jq curl git golang ffuf npm && \
go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
go install github.com/tomnomnom/assetfinder@latest && \
go install github.com/lc/gau/v2/cmd/gau@latest && \
go install github.com/tomnomnom/waybackurls@latest && \
sudo npm install -g wappalyzer
```

---

# ✅ Step 4 — Verify Installation

Check tools are working:

```bash
subfinder -h
httpx -h
ffuf -h
wappalyzer --help
```

If commands show help menu → ✔ Ready.

---

# 🌎 Step 5 — Optional Global Installation

Run tool from anywhere:

```bash
sudo ln -s $(pwd)/Reconer.sh /usr/local/bin/Reconer
```

Now you can run:

```bash
Reconer target.com
```

---

# 🚀 Step 6 — Run Reconer

Basic usage:

```bash
./Reconer.sh example.com
```

OR:

```bash
Reconer example.com
```

---

# 🧠 What Happens Automatically (Execution Flow)

Reconer runs stages in this order:

---

## 🔎 Phase 1 — Subdomain Enumeration

Tool collects subdomains from:

* crt.sh
* subfinder
* assetfinder
* passive intelligence sources

📄 Output:

```
subdomains.txt
```

---

## 🌐 Phase 2 — Live Host Detection

Checks which domains are alive.

📄 Output:

```
live_hosts.txt
```

---

## 🧬 Phase 3 — Technology Detection

Detects:

* Programming language
* Framework
* CMS
* Server
* CDN

(using Wappalyzer)

📄 Output:

```
technologies.txt
```

---

## 🔗 Phase 4 — URL & Endpoint Collection

Collects URLs from:

* Wayback Machine
* GAU
* Historical sources

📄 Output:

```
all_urls.txt
endpoints.txt
```

---

## 📜 Phase 5 — JavaScript Analysis

Extracts endpoints from JS files.

Finds:

* hidden routes
* API calls
* tokens
* internal paths

📄 Output:

```
js_endpoints.txt
```

---

## 🔐 Phase 6 — API Endpoint Discovery

Searches for:

```
/api
/graphql
/rest
/v1
/internal
```

📄 Output:

```
api_endpoints.txt
```

---

## 🧨 Phase 7 — Sensitive File Discovery

Checks huge GitHub wordlists for:

* `.env`
* backup files
* config files
* admin panels
* secrets

📄 Output:

```
sensitive_files.txt
```

---

## 📊 Phase 8 — Report Generation

Creates visual report:

```
report.html
```

Open it:

```bash
open output/example.com/report.html
```

---

# 📂 Step 7 — Understand Output Folder

```
output/
 └── example.com/
      ├── subdomains.txt
      ├── live_hosts.txt
      ├── technologies.txt
      ├── endpoints.txt
      ├── js_endpoints.txt
      ├── api_endpoints.txt
      ├── sensitive_files.txt
      ├── all_urls.txt
      └── report.html
```

---

# 🎯 Step 8 — How Bug Hunters Use Results

After recon:

✅ Find attack surface
✅ Search parameters
✅ Test authentication
✅ Test APIs
✅ Look for secrets
✅ Start vulnerability hunting

Typical flow:

```
Subdomains → Endpoints → Parameters → Vulnerabilities
```

---

# 🔥 Recommended Hunting Flow

```
1. Run Reconer
2. Open report.html
3. Check APIs first
4. Analyze JS endpoints
5. Hunt parameters
6. Test high-value targets
```

---

# ⚠️ Important Notes

✔ Use only on authorized targets
✔ Follow bug bounty scope
✔ Respect rate limits
✔ Avoid aggressive scanning

---

If you want, next I can help you add **what top 1% bug bounty hunters actually do AFTER recon** — the real money workflow.
