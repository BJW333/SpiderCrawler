import sys
import os
import subprocess
import re
import json
import queue
import socket
import threading
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
import requests
from shodan import Shodan
from shutil import which
import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, BooleanVar, Label, Checkbutton, Radiobutton
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

#Config 
SHODAN_API_KEY = 'jxLW13mSmgc5PYI3kK1YqUXWvzGZXpbO'
if not SHODAN_API_KEY:
    print("[WARNING] SHODAN_API_KEY not set. Export it as an environment variable.")
    print("  export SHODAN_API_KEY='your_key_here'")

shodan_api = Shodan(SHODAN_API_KEY)

OLLAMA_BASE_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
SPIDERCRAWLER_MODEL = "spidercrawler"

NMAP_TIMEOUT = 600
SEARCHSPLOIT_TIMEOUT = 60
REQUEST_TIMEOUT = 10
CVE_THREAD_POOL_SIZE = 5

#States (guarded by lock)
state_lock = threading.Lock()
cveportsgraphdata = {}
graph_canvas = None
graph_figure = None
gui_queue = queue.Queue()
last_scan_data = None


#Utility Functions 
def is_valid_ip(addr):
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False

def is_valid_domain(domain):
    pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$")
    return bool(pattern.match(domain))

def check_binary(name):
    return which(name) is not None

def gui_safe(func, *args):
    root.after(0, func, *args)


#SpiderCrawler AI (Ollama)
def check_model_available():
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            return SPIDERCRAWLER_MODEL in models or f"{SPIDERCRAWLER_MODEL}:latest" in models
    except Exception:
        pass
    return False

def query_ai_streaming(scan_data, prompt_override=None):
    if not check_model_available():
        gui_queue.put(f"\n[AI] Model '{SPIDERCRAWLER_MODEL}' not found in Ollama.\n")
        gui_queue.put("[AI] Run: bash setup_spidercrawler_model.sh\n\n")
        return

    if prompt_override:
        user_msg = prompt_override
    else:
        user_msg = f"Analyze this scan and if there are any vulnerabilities write a corresponding exploit script to run:\n\n{json.dumps(scan_data, indent=2)}"

    gui_queue.put("\n══════════════════════════════════════════════════════════════\n")
    gui_queue.put(" SPIDERCRAWLER AI ANALYSIS\n")
    gui_queue.put("══════════════════════════════════════════════════════════════\n\n")

    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": SPIDERCRAWLER_MODEL,
                "messages": [
                    {"role": "user", "content": user_msg}
                ],
                "stream": True,
            },
            stream=True,
            timeout=(30, 600),
        )
        resp.raise_for_status()

        full_response = []
        for line in resp.iter_lines():
            if line:
                try:
                    chunk = json.loads(line)
                    token = chunk.get("message", {}).get("content", "")
                    if token:
                        gui_queue.put(token)
                        full_response.append(token)
                    if chunk.get("done", False):
                        break
                except json.JSONDecodeError:
                    continue

        gui_queue.put("\n\n══════════════════════════════════════════════════════════════\n")
        gui_queue.put(" END OF AI ANALYSIS\n")
        gui_queue.put("══════════════════════════════════════════════════════════════\n\n")

        full_text = "".join(full_response)
        if "```" in full_text:
            extract_and_save_scripts(full_text)

    except requests.exceptions.ConnectionError:
        gui_queue.put("\n[AI] Cannot connect to Ollama. Is it running?\n")
        gui_queue.put(f"[AI] Expected at: {OLLAMA_BASE_URL}\n\n")
    except Exception as e:
        gui_queue.put(f"\n[AI] Error: {e}\n\n")

def query_ai_with_followup(question):
    global last_scan_data
    if last_scan_data is None:
        gui_queue.put("[AI] No scan data loaded. Run a scan first.\n")
        return

    prompt = (
        f"Based on this scan data:\n\n{json.dumps(last_scan_data, indent=2)}\n\n"
        f"Answer this question: {question}"
    )
    query_ai_streaming(last_scan_data, prompt_override=prompt)

def extract_and_save_scripts(ai_text):
    """Pull code fences from AI output, save to ./scripts/ with CVE-based names."""
    os.makedirs("./scripts", exist_ok=True)
    
    pattern = re.compile(r"```(\w+)?\n(.*?)```", re.DOTALL)
    matches = pattern.findall(ai_text)
    
    saved = []
    for i, (lang, code) in enumerate(matches):
        lang = lang.lower() if lang else "txt"
        ext_map = {"python": "py", "bash": "sh", "sh": "sh", "ruby": "rb", "perl": "pl", "go": "go", "c": "c", "cpp": "cpp"}
        ext = ext_map.get(lang, lang if lang else "txt")
        
        # Try to pull a CVE ID from the code block content
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", code)
        if cve_match:
            name = cve_match.group().lower()
        else:
            name = f"script_{i}"
        
        filename = f"./scripts/{name}.{ext}"
        # Don't overwrite — append a number
        counter = 1
        base = filename
        while os.path.exists(filename):
            filename = base.replace(f".{ext}", f"_{counter}.{ext}")
            counter += 1
        
        with open(filename, "w") as f:
            f.write(code.strip() + "\n")
        
        saved.append(filename)
        gui_queue.put(f"[SCRIPT] Saved → {filename}\n")
    
    return saved

def open_cve_picker():
    """Popup window with checkboxes for each CVE found in the last scan. User picks which ones to generate code for."""
    global last_scan_data
    if last_scan_data is None:
        gui_queue.put("[AI] No scan data. Run a scan first.\n")
        return

    # Collect all unique CVEs from scan data
    all_cves = []
    for target in last_scan_data.get("targets", []):
        for port_entry in target.get("ports", []):
            for cve in port_entry.get("cves", []):
                cve_id = cve.get("id", "")
                summary = cve.get("summary", "")[:80]
                cvss = cve.get("cvss", "?")
                port = port_entry.get("port", "?")
                if cve_id and cve_id not in [c[0] for c in all_cves]:
                    all_cves.append((cve_id, port, cvss, summary))

    if not all_cves:
        gui_queue.put("[AI] No CVEs found in scan data.\n")
        return

    # Build popup
    picker = tk.Toplevel(root)
    picker.title("Select CVEs for Exploit Generation")
    picker.geometry("700x500")
    picker.transient(root)
    picker.grab_set()

    tk.Label(picker, text="Select CVEs to generate exploit code for:", font=("TkDefaultFont", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 5))

    # Scrollable frame for checkboxes
    canvas = tk.Canvas(picker)
    scrollbar = ttk.Scrollbar(picker, orient="vertical", command=canvas.yview)
    scroll_frame = tk.Frame(canvas)

    scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

    # Create a BooleanVar + checkbox for each CVE
    cve_vars = {}
    for cve_id, port, cvss, summary in all_cves:
        var = BooleanVar(value=True)
        cve_vars[cve_id] = var
        label = f"{cve_id}  |  Port {port}  |  CVSS {cvss}  |  {summary}"
        Checkbutton(scroll_frame, text=label, variable=var, anchor="w", wraplength=650).pack(anchor="w", fill=tk.X)

    # Buttons
    btn_frame = tk.Frame(picker)
    btn_frame.pack(fill=tk.X, padx=10, pady=10)

    def select_all():
        for v in cve_vars.values():
            v.set(True)

    def select_none():
        for v in cve_vars.values():
            v.set(False)

    def generate():
        selected = [cid for cid, var in cve_vars.items() if var.get()]
        picker.destroy()
        if not selected:
            gui_queue.put("[AI] No CVEs selected.\n")
            return

        # Build a filtered scan dict with only selected CVEs
        filtered = filter_scan_by_cves(last_scan_data, selected)
        prompt = f"Write exploit scripts for these specific CVEs only:\n\n{json.dumps(filtered, indent=2)}"
        Thread(target=query_ai_streaming, args=(filtered, prompt), daemon=True).start()

    tk.Button(btn_frame, text="All", command=select_all).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame, text="None", command=select_none).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame, text="Generate Exploits", command=generate).pack(side=tk.RIGHT, padx=2)
    tk.Button(btn_frame, text="Cancel", command=picker.destroy).pack(side=tk.RIGHT, padx=2)


def filter_scan_by_cves(scan_data, selected_cves):
    """Return a copy of scan_data containing only the selected CVE IDs."""
    filtered = {"targets": [], "cve_count": 0}
    count = 0
    for target in scan_data.get("targets", []):
        new_target = {"ip": target.get("ip", ""), "ports": []}
        for port_entry in target.get("ports", []):
            new_port = {
                "port": port_entry.get("port"),
                "cves": [],
                "source": port_entry.get("source", {})
            }
            for cve in port_entry.get("cves", []):
                if cve.get("id") in selected_cves:
                    new_port["cves"].append(cve)
                    count += 1
            if new_port["cves"]:
                new_target["ports"].append(new_port)
        if new_target["ports"]:
            filtered["targets"].append(new_target)
    filtered["cve_count"] = count
    return filtered

#Graph Generation
def display_open_ports_bar_chart(port_cve_counts, results_frame):
    global graph_figure, graph_canvas

    if graph_figure is None:
        graph_figure, ax = plt.subplots(figsize=(5, 3))
    else:
        ax = graph_figure.gca()
        ax.clear()

    ports = list(port_cve_counts.keys())
    counts = list(port_cve_counts.values())

    ax.bar(ports, counts, color="#2196F3")
    ax.set_xlabel("Port")
    ax.set_ylabel("CVE Count")
    ax.set_title("CVEs per Open Port")
    graph_figure.tight_layout()

    if graph_canvas is None:
        graph_canvas = FigureCanvasTkAgg(graph_figure, master=results_frame)
        graph_canvas.draw()
        graph_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    else:
        graph_canvas.draw()

def show_ports_graph():
    global cveportsgraphdata, graph_canvas, graph_figure

    with state_lock:
        data = dict(cveportsgraphdata) if cveportsgraphdata else {}

    if not data:
        gui_queue.put("No CVE port data available. Run a scan first.\n")
        return

    if graph_canvas is not None:
        graph_canvas.get_tk_widget().destroy()
        graph_canvas = None
        graph_figure = None
    else:
        display_open_ports_bar_chart(data, resultsframe)

#Scanning
def scan_ip_for_open_ports(ip, options, timing="T4"):
    if not check_binary("nmap"):
        gui_queue.put("[ERROR] nmap not found on PATH. Install it first.\n")
        return [], {}

    cmd = ["nmap", ip]

    if options["fast_scan"].get():
        cmd.append("-F")
    if options["show_open"].get():
        cmd.append("--open")
    if options["version_detection"].get():
        cmd.append("-sV")
    if options["os_detection"].get():
        cmd.append("-O")
    if options["script_scan"].get():
        cmd.append("-sC")
    if options["aggressive_scan"].get():
        cmd.append("-A")
    if options["no_ping"].get():
        cmd.append("-Pn")
    if options["stealth_scan"].get():
        cmd.append("-sS")
    if options["udp_scan"].get():
        cmd.append("-sU")
    if options["vulnerability_scan"].get():
        cmd.append("--script=vulners")

    cmd.append(f"-{timing}")

    try:
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.check_output(cmd, universal_newlines=True, timeout=NMAP_TIMEOUT)
        return parse_nmap_vuln_output(result)
    except subprocess.TimeoutExpired:
        gui_queue.put(f"[ERROR] nmap timed out after {NMAP_TIMEOUT}s for {ip}\n")
        return [], {}
    except Exception as e:
        gui_queue.put(f"[ERROR] Scanning {ip}: {e}\n")
        return [], {}

def parse_nmap_vuln_output(nmap_output):
    open_ports = []
    nmap_vulnerabilities = {}
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
    port = None

    for line in nmap_output.split("\n"):
        if ("/tcp" in line or "/udp" in line) and "open" in line:
            port = line.split("/")[0].strip()
            open_ports.append(port)
        if "CVE" in line and port:
            matches = cve_pattern.findall(line)
            if matches:
                if port not in nmap_vulnerabilities:
                    nmap_vulnerabilities[port] = []
                nmap_vulnerabilities[port].extend(matches)

    return open_ports, nmap_vulnerabilities

def get_vulnerabilities_from_shodan(ip, ports):
    vulnerabilities = {}
    try:
        host_info = shodan_api.host(ip)
        for port in ports:
            service_info = host_info.get("data", [])
            for service in service_info:
                if service.get("port") == int(port):
                    vulns = service.get("vulns", [])
                    vulnerabilities[port] = vulns
        return vulnerabilities
    except Exception as e:
        gui_queue.put(f"[ERROR] Shodan lookup for {ip}: {e}\n")
        return {}

def search_exploitdb(all_cve_ids):
    if not check_binary("searchsploit"):
        gui_queue.put("[WARNING] searchsploit not found on PATH. Skipping ExploitDB.\n")
        return {}

    exploits = {}
    for cve_id in all_cve_ids:
        try:
            result = subprocess.run(
                ["searchsploit", "--json", cve_id],
                capture_output=True, text=True,
                timeout=SEARCHSPLOIT_TIMEOUT
            )
            if result.returncode == 0:
                exploits[cve_id] = result.stdout
                output = f"Results for {cve_id}:\n{result.stdout}\n"
            else:
                msg = f"searchsploit: no results for {cve_id}\n"
                exploits[cve_id] = msg
                output = msg
        except subprocess.TimeoutExpired:
            output = f"searchsploit timed out for {cve_id}\n"
            exploits[cve_id] = output
        except Exception as e:
            output = f"Error searching ExploitDB for {cve_id}: {e}\n"
            exploits[cve_id] = output
        gui_queue.put(output)

    return exploits

#CVE Detail Fetching (thread-pooled)
def fetch_cve_detail(cve_id):
    """Fetch CVE info from CIRCL Vulnerability-Lookup (new API) with NVD fallback."""
    try:
        url = f"https://vulnerability.circl.lu/api/cve/{cve_id}"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            if data:
                # Normalize to the format the rest of the code expects
                containers = data.get("containers", {})
                cna = containers.get("cna", {})
                descriptions = cna.get("descriptions", [])
                summary = ""
                for desc in descriptions:
                    if desc.get("lang", "en") == "en":
                        summary = desc.get("value", "")
                        break
                if not summary and descriptions:
                    summary = descriptions[0].get("value", "")

                refs = [r.get("url", "") for r in cna.get("references", [])]

                metrics = cna.get("metrics", [])
                cvss = None
                for m in metrics:
                    for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                        if key in m:
                            cvss = m[key].get("baseScore")
                            break
                    if cvss:
                        break

                return cve_id, {
                    "id": cve_id,
                    "summary": summary,
                    "cvss": cvss,
                    "references": refs
                }
    except Exception:
        pass

    # Fallback to NVD API
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                descriptions = cve_data.get("descriptions", [])
                summary = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        summary = desc.get("value", "")
                        break

                refs = [r.get("url", "") for r in cve_data.get("references", [])]

                metrics = cve_data.get("metrics", {})
                cvss = None
                for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                        break

                return cve_id, {
                    "id": cve_id,
                    "summary": summary,
                    "cvss": cvss,
                    "references": refs
                }
    except Exception as e:
        gui_queue.put(f"[ERROR] CVE fetch {cve_id}: {e}\n")

    return cve_id, None

def display_cve_detail_to_gui(cve_id, cve_details):
    if not cve_details:
        gui_queue.put(f"No details available for {cve_id}.\n")
        return

    output = "\n---------------------------------------------------------------------\n"
    output += f"\nDetails for CVE: {cve_details.get('id', cve_id)}\n\n"
    output += f"Summary: {cve_details.get('summary', 'N/A')}\n"
    output += "---------------------------------------------------------------------\n"

    refs = cve_details.get("references", [])
    if refs:
        output += "\nReferences:\n"
        for ref in refs[:5]:
            output += f"  {ref}\n"
    else:
        output += "\nNo references available.\n"

    output += "---------------------------------------------------------------------\n"
    search_url = f"https://github.com/search?q={cve_id}+exploit&type=Repositories"
    output += f"\nGitHub search: {search_url}\n"
    google_url = f"https://www.google.com/search?q={cve_id}+exploit"
    output += f"Google search: {google_url}\n"
    output += "---------------------------------------------------------------------\n"
    gui_queue.put(output)

def process_cve_ids_pooled(cve_ids):
    unique_ids = list(set(cve_ids))
    cve_details = {}

    with ThreadPoolExecutor(max_workers=CVE_THREAD_POOL_SIZE) as pool:
        futures = {pool.submit(fetch_cve_detail, cid): cid for cid in unique_ids}
        for future in futures:
            cve_id, detail = future.result()
            cve_details[cve_id] = detail
            display_cve_detail_to_gui(cve_id, detail)

    return cve_details

#IP Camera Check
def findipcam(ip, ports):
    cam_ports = {"80", "443", "554", "8080", "8443"}
    open_cam_ports = set(ports) & cam_ports
    if not open_cam_ports:
        return

    output = "\nPotential IP camera endpoints:\n"
    for p in sorted(open_cam_ports, key=int):
        proto = "https" if p in {"443", "8443"} else "http"
        output += f"  {proto}://{ip}:{p}\n"
    output += "------------------------------------\n"
    gui_queue.put(output)

#IP Info
def ipinfo():
    target = Ip_entry.get().strip()
    if not target:
        gui_queue.put("Please insert an IP to get info on.\n")
        return

    try:
        data = requests.get(f"https://ipapi.co/{target}/json/", timeout=REQUEST_TIMEOUT).json()
        output = [
            f"[Target]: {data.get('ip', 'Unknown')}",
            f"[ISP]: {data.get('org', 'Unknown')}",
            f"[City]: {data.get('city', 'Unknown')}",
            f"[Region]: {data.get('region', 'Unknown')}",
            f"[Longitude]: {data.get('longitude', 'Unknown')}",
            f"[Latitude]: {data.get('latitude', 'Unknown')}",
            f"[Timezone]: {data.get('timezone', 'Unknown')}",
            f"[Postal]: {data.get('postal', 'Unknown')}",
        ]
        gui_queue.put("\n".join(output) + "\n\n")
    except Exception as e:
        gui_queue.put(f"[ERROR] IP info lookup: {e}\n")

#Domain -> IP
def get_ip_website():
    domain = website_entry.get().strip()
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]

    domain = domain.rstrip("/")

    if not is_valid_domain(domain):
        gui_queue.put(f"Invalid domain: {domain}\n")
        return

    try:
        ip_address = socket.gethostbyname(domain)
        gui_queue.put(f"{domain} → {ip_address}\n")
    except socket.gaierror as e:
        gui_queue.put(f"Error resolving {domain}: {e}\n")


#Scan Data Builder
def build_scan_dict(ip, ports, nmap_vulns, shodan_vulns, exploitdb_results, cve_details, all_cve_ids):
    target = {"ip": ip, "ports": []}

    for port in ports:
        nmap_cves = set(nmap_vulns.get(port, []))
        shodan_cves = set(shodan_vulns.get(port, []))
        merged = sorted(nmap_cves | shodan_cves)

        port_entry = {
            "port": int(port),
            "cves": [],
            "source": {"nmap": sorted(nmap_cves), "shodan": sorted(shodan_cves)}
        }
        for cve_id in merged:
            cve_entry = {"id": cve_id}
            if cve_details and cve_id in cve_details and cve_details[cve_id]:
                detail = cve_details[cve_id]
                cve_entry["summary"] = detail.get("summary", "")
                cve_entry["cvss"] = detail.get("cvss")
                cve_entry["references"] = detail.get("references", [])[:10]
            if exploitdb_results and cve_id in exploitdb_results:
                raw = exploitdb_results[cve_id]
                try:
                    cve_entry["exploitdb"] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    cve_entry["exploitdb_raw"] = str(raw)
            port_entry["cves"].append(cve_entry)

        target["ports"].append(port_entry)

    return {"targets": [target], "cve_count": len(all_cve_ids)}


#Core Analysis (single IP)
def analyze_single_ip(ip):
    global cveportsgraphdata

    output = f"Analyzing IP: {ip}\n---------------------------------\n"
    all_cve_ids = []

    ports, nmap_vulns = scan_ip_for_open_ports(ip, options, timing.get())

    output += "Open ports:\n"
    for port in ports:
        output += f"  - Port {port}\n"
    output += "\n---------------------------------------------------------------------\n"

    shodan_vulns = get_vulnerabilities_from_shodan(ip, ports)

    all_vulnerabilities = {}
    port_cve_counts = {}

    for port in ports:
        merged = set(shodan_vulns.get(port, [])) | set(nmap_vulns.get(port, []))
        all_vulnerabilities[port] = sorted(merged)
        port_cve_counts[port] = len(merged)

    for port, vulns in all_vulnerabilities.items():
        output += f"\nVulnerabilities for Port {port}:\n"
        if vulns:
            for vuln in vulns:
                output += f"  - {vuln}\n"
                all_cve_ids.append(vuln)
        else:
            output += "  - None found\n"

    output += "\n---------------------------------------------------------------------\n\n"
    gui_queue.put(output)

    with state_lock:
        cveportsgraphdata = port_cve_counts

    findipcam(ip, ports)
    exploitdb_results = search_exploitdb(all_cve_ids)

    cve_details = {}
    if all_cve_ids:
        cve_details = process_cve_ids_pooled(all_cve_ids)

    return ports, nmap_vulns, shodan_vulns, exploitdb_results, cve_details, all_cve_ids


#GUI Analysis Wrappers
def analyze_ip_gui():
    global last_scan_data

    target = Ip_entry.get().strip()
    if not target:
        gui_queue.put("Please insert an IP target to scan.\n")
        return

    if not is_valid_ip(target):
        gui_queue.put(f"Invalid IP address: {target}\n")
        return

    gui_safe(progress_bar.start, 2)

    try:
        ports, nmap_vulns, shodan_vulns, exploitdb_results, cve_details, cve_ids = (
            analyze_single_ip(target)
        )

        scan_dict = build_scan_dict(
            target, ports, nmap_vulns, shodan_vulns,
            exploitdb_results, cve_details, cve_ids
        )
        last_scan_data = scan_dict

        if cve_ids and auto_ai_var.get():
            gui_queue.put("\n[AI] Sending scan data to SpiderCrawler AI...\n")
            query_ai_streaming(scan_dict)

    except Exception as e:
        gui_queue.put(f"An error occurred: {e}\n")
    finally:
        gui_safe(progress_bar.stop)

def analyze_file_gui():
    global last_scan_data

    ip_file = file_entry.get().strip()
    if not ip_file:
        gui_queue.put("Please select a file.\n")
        return

    gui_safe(progress_bar.start, 2)
    all_targets = []

    try:
        with open(ip_file, "r") as f:
            ips = [line.strip() for line in f if line.strip()]

        for ip in ips:
            if not is_valid_ip(ip):
                gui_queue.put(f"Skipping invalid IP: {ip}\n")
                continue

            ports, nmap_vulns, shodan_vulns, exploitdb_results, cve_details, cve_ids = (
                analyze_single_ip(ip)
            )

            scan_dict = build_scan_dict(
                ip, ports, nmap_vulns, shodan_vulns,
                exploitdb_results, cve_details, cve_ids
            )
            all_targets.extend(scan_dict["targets"])

        combined = {"targets": all_targets, "target_count": len(all_targets)}
        last_scan_data = combined

        if all_targets and auto_ai_var.get():
            gui_queue.put("\n[AI] Sending batch scan data to SpiderCrawler AI...\n")
            query_ai_streaming(combined)

    except FileNotFoundError:
        gui_queue.put(f"File not found: {ip_file}\n")
    except Exception as e:
        gui_queue.put(f"An error occurred: {e}\n")
    finally:
        gui_safe(progress_bar.stop)


#AI Controls
def run_ai_analysis():
    global last_scan_data
    if last_scan_data is None:
        gui_queue.put("[AI] No scan data. Run a scan first.\n")
        return
    Thread(target=query_ai_streaming, args=(last_scan_data,), daemon=True).start()

def ask_ai():
    question = ai_entry.get().strip()
    if not question:
        gui_queue.put("[AI] Enter a question first.\n")
        return
    ai_entry.delete(0, tk.END)
    Thread(target=query_ai_with_followup, args=(question,), daemon=True).start()

def load_scan_json():
    global last_scan_data
    path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
    if not path:
        return
    try:
        with open(path, "r") as f:
            last_scan_data = json.load(f)
        gui_queue.put(f"[AI] Loaded scan data from {path}\n")
    except Exception as e:
        gui_queue.put(f"[AI] Error loading: {e}\n")

#Threaded Launchers 
def analyze_threaded_ip():
    Thread(target=analyze_ip_gui, daemon=True).start()

def analyze_threaded_file():
    Thread(target=analyze_file_gui, daemon=True).start()

def threaded_ipinfo():
    Thread(target=ipinfo, daemon=True).start()

def threaded_website_ip():
    Thread(target=get_ip_website, daemon=True).start()

#open scripts dir
def _open_scripts_dir():
    os.makedirs("./scripts", exist_ok=True)
    if sys.platform == "darwin":
        subprocess.Popen(["open", "./scripts"])
    elif sys.platform == "win32":
        os.startfile("./scripts")
    else:
        subprocess.Popen(["xdg-open", "./scripts"])
        
#File Browser 
def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

#GUI Helpers
def clear_view():
    results_text.delete(1.0, tk.END)

def exit_program():
    root.destroy()

def process_gui_queue():
    try:
        while True:
            result = gui_queue.get_nowait()
            results_text.insert(tk.END, result)
            results_text.see(tk.END)
    except queue.Empty:
        pass
    root.after(100, process_gui_queue)


#══════════════════════════════════════════════════════════════
#GUI LAYOUT
#══════════════════════════════════════════════════════════════
root = tk.Tk()
root.title("SpiderCrawler")
root.geometry("1200x1000")
root.resizable(True, True)

#Left panel (controls)
left_panel = tk.Frame(root, padx=10, pady=10)
left_panel.pack(side=tk.LEFT, fill=tk.Y)

#IP target
ip_frame = tk.Frame(left_panel)
ip_frame.pack(fill=tk.X, pady=(0, 5))

tk.Label(ip_frame, text="IP Target:").pack(side=tk.LEFT)
Ip_entry = tk.Entry(ip_frame, width=16)
Ip_entry.pack(side=tk.LEFT, padx=5)

#Scan options
options = {
    "fast_scan": BooleanVar(value=False),
    "show_open": BooleanVar(value=False),
    "version_detection": BooleanVar(value=False),
    "os_detection": BooleanVar(value=False),
    "script_scan": BooleanVar(value=False),
    "aggressive_scan": BooleanVar(value=False),
    "no_ping": BooleanVar(value=False),
    "stealth_scan": BooleanVar(value=False),
    "udp_scan": BooleanVar(value=False),
    "vulnerability_scan": BooleanVar(value=False),
}

scan_labels = {
    "fast_scan": "Fast Scan (-F)",
    "show_open": "Show Open Only (--open)",
    "version_detection": "Version Detection (-sV)",
    "os_detection": "OS Detection (-O)",
    "script_scan": "Script Scan (-sC)",
    "aggressive_scan": "Aggressive (-A)",
    "no_ping": "No Ping (-Pn)",
    "stealth_scan": "Stealth SYN (-sS)",
    "udp_scan": "UDP Scan (-sU)",
    "vulnerability_scan": "Vuln Scan (--script vulners)",
}

for key, label in scan_labels.items():
    Checkbutton(left_panel, text=label, var=options[key]).pack(anchor="w")

#Timing
Label(left_panel, text="Timing:").pack(anchor="w", pady=(5, 0))
timing = tk.StringVar(value="T4")
timing_frame = tk.Frame(left_panel)
timing_frame.pack(anchor="w")
for t in ["T2", "T3", "T4", "T5"]:
    Radiobutton(timing_frame, text=t, value=t, variable=timing).pack(side=tk.LEFT)

#IP buttons
ip_btn_frame = tk.Frame(left_panel)
ip_btn_frame.pack(fill=tk.X, pady=5)
tk.Button(ip_btn_frame, text="Scan IP", command=analyze_threaded_ip).pack(side=tk.LEFT, padx=2)
tk.Button(ip_btn_frame, text="IP Info", command=threaded_ipinfo).pack(side=tk.LEFT, padx=2)
tk.Button(ip_btn_frame, text="Ports Graph", command=show_ports_graph).pack(side=tk.LEFT, padx=2)

#Domain lookup
tk.Label(left_panel, text="Domain:").pack(anchor="w", pady=(10, 0))
domain_frame = tk.Frame(left_panel)
domain_frame.pack(fill=tk.X)
website_entry = tk.Entry(domain_frame, width=22)
website_entry.pack(side=tk.LEFT, padx=(0, 5))
tk.Button(domain_frame, text="Resolve", command=threaded_website_ip).pack(side=tk.LEFT)

#File scan
tk.Label(left_panel, text="IP List File:").pack(anchor="w", pady=(10, 0))
file_frame = tk.Frame(left_panel)
file_frame.pack(fill=tk.X)
file_entry = tk.Entry(file_frame, width=18)
file_entry.pack(side=tk.LEFT, padx=(0, 5))
tk.Button(file_frame, text="Browse", command=select_file).pack(side=tk.LEFT, padx=2)
tk.Button(file_frame, text="Scan File", command=analyze_threaded_file).pack(side=tk.LEFT, padx=2)

#AI Controls 
ttk.Separator(left_panel, orient="horizontal").pack(fill=tk.X, pady=10)

tk.Label(left_panel, text="SpiderCrawler AI", font=("TkDefaultFont", 11, "bold")).pack(anchor="w")

auto_ai_var = BooleanVar(value=False)
Checkbutton(left_panel, text="Auto-analyze after scan", var=auto_ai_var).pack(anchor="w")

ai_btn_frame = tk.Frame(left_panel)
ai_btn_frame.pack(fill=tk.X, pady=5)
tk.Button(ai_btn_frame, text="Run AI Analysis", command=run_ai_analysis).pack(side=tk.LEFT, padx=2)
tk.Button(ai_btn_frame, text="Pick CVEs", command=open_cve_picker).pack(side=tk.LEFT, padx=2)
tk.Button(ai_btn_frame, text="Load JSON", command=load_scan_json).pack(side=tk.LEFT, padx=2)
tk.Button(ai_btn_frame, text="Open Scripts", command=_open_scripts_dir).pack(side=tk.LEFT, padx=2)


tk.Label(left_panel, text="Ask AI:").pack(anchor="w", pady=(5, 0))
ai_input_frame = tk.Frame(left_panel)
ai_input_frame.pack(fill=tk.X)
ai_entry = tk.Entry(ai_input_frame, width=22)
ai_entry.pack(side=tk.LEFT, padx=(0, 5))
tk.Button(ai_input_frame, text="Ask", command=ask_ai).pack(side=tk.LEFT)
ai_entry.bind("<Return>", lambda e: ask_ai())

#Right panel (results) 
resultsframe = tk.Frame(root, padx=10, pady=10)
resultsframe.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

progress_bar = ttk.Progressbar(resultsframe, orient="horizontal", mode="indeterminate", length=280)
progress_bar.pack(fill=tk.X, pady=(0, 5))

btn_frame = tk.Frame(resultsframe)
btn_frame.pack(fill=tk.X, pady=(0, 5))
tk.Button(btn_frame, text="Clear", command=clear_view).pack(side=tk.LEFT, padx=2)
tk.Button(btn_frame, text="Exit", command=exit_program).pack(side=tk.RIGHT, padx=2)

results_text = scrolledtext.ScrolledText(resultsframe, width=80, height=35)
results_text.pack(fill=tk.BOTH, expand=True)

#Start
process_gui_queue()
root.mainloop()
