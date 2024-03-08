import sys
import subprocess
from shodan import Shodan
import requests
#from msfconsole import MsfConsole
import tkinter as tk
from tkinter import scrolledtext
from tkinter import filedialog
from threading import Thread
import socket
from tkinter import ttk


# Replace 'YOUR_SHODAN_API_KEY' with your actual Shodan API key
SHODAN_API_KEY = 'jxLW13mSmgc5PYI3kK1YqUXWvzGZXpbO'
shodan_api = Shodan(SHODAN_API_KEY)

# Command to open a new Terminal window and run the commands below

def runmetasploit():
    #runmetasploitterminal = input("do you want to run metasploit yes or no: ")
    #print("working")
    if runmetasploitterminal.lower() == ("yes"):
        commands = '''
        /opt/metasploit-framework/bin/msfconsole
        msfrpcd -P password -S -f
        '''
        command = f'osascript -e \'tell app "Terminal" to do script "{commands}"\''
        subprocess.run(["/bin/bash", "-c", command])
    elif runmetasploitterminal.lower() == ("no"):
        dontwannarunmeta = "Metasploit running canceled"
        return print(dontwannarunmeta)

runmetasploitterminal = input("Do you want to run Metasploit yes or no: ")
runmetasploit()

# Initialize Metasploit Console
MSF_RPC_HOST = "127.0.0.1"
MSF_RPC_PORT = "55553"
MSF_RPC_URL = f"http://{MSF_RPC_HOST}:{MSF_RPC_PORT}/api/"
MSF_RPC_USER = "msf"  # Default user
MSF_RPC_PASSWORD = "password"  # The password you set when starting the RPC server

def authenticate_rpc():
    try:
        response = requests.post(MSF_RPC_URL + 'auth', json={"username": MSF_RPC_USER, "password": MSF_RPC_PASSWORD})
        if response.status_code == 200:
            return response.json()['token']
        else:
            print("Failed to authenticate with Metasploit RPC server.")
            return None
    except Exception as e:
        print(f"Error during authentication with Metasploit RPC server: {e}")
        return None

def execute_rpc_command(token, method, params=[]):
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    data = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': method,
        'params': params
    }
    try:
        response = requests.post(MSF_RPC_URL + 'execute', headers=headers, json=data)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"RPC command execution failed: {response.text}")
            return None
    except Exception as e:
        print(f"Error executing RPC command: {e}")
        return None
    
    
    
    
    
def scan_ip_for_open_ports(ip):
    # Using Nmap for port scanning. Ensure nmap is installed in your system.
    try:
        result = subprocess.check_output(['nmap', '--open', '-T4', ip], universal_newlines=True)
        open_ports = []
        for line in result.split('\n'):
            if '/tcp' in line and 'open' in line:
                port = line.split('/')[0].strip()
                open_ports.append(port)
        return open_ports
    except Exception as e:
        print(f"Error scanning {ip} for open ports: {e}")
        return []

def get_vulnerabilities_from_shodan(ip, ports):
    vulnerabilities = {}
    try:
        host_info = shodan_api.host(ip)
        for port in ports:
            service_info = host_info.get('data', [])
            for service in service_info:
                if service.get('port') == int(port):
                    vulns = service.get('vulns', [])
                    vulnerabilities[port] = vulns
        return vulnerabilities
    except Exception as e:
        print(f"Error retrieving vulnerabilities from Shodan for {ip}: {e}")
        return {}

def search_exploitdb(vulns):
    exploits = {}
    for vuln in vulns:
        try:
            response = requests.get(f'https://www.exploit-db.com/search?cve={vuln}')
            if response.status_code == 200:
                exploits[vuln] = response.url
        except Exception as e:
            print(f"Error searching ExploitDB for {vuln}: {e}")
    return exploits

def analyze_ip(ip):
    print(f"Analyzing IP: {ip}")
    open_ports = scan_ip_for_open_ports(ip)
    print(f"Open ports: {open_ports}")
    vulnerabilities = get_vulnerabilities_from_shodan(ip, open_ports)
    for port, vulns in vulnerabilities.items():
        print(f"Port {port} vulnerabilities: {vulns}")
        exploits = search_exploitdb(vulns)
        for vuln, exploit_url in exploits.items():
            print(f"\t{vuln}: {exploit_url}")

if __name__ == "__main__":  
    #if len(sys.argv) != 2:
       # print("Usage: python3 script.py <file_with_ips.txt>")
        #sys.exit(1)
    print("Program started")

    
def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)    
    
        
def analyze_file_gui():
    ip_file = file_entry.get()
    if not ip_file:
        results_text.insert(tk.INSERT, "Please select a file.\n")
        return
    try:
        with open(ip_file, 'r') as file:
            for ip in file:
                ip = ip.strip()
                if ip:
                    results_text.insert(tk.INSERT, f"Analyzing IP: {ip}\n")
                    open_ports = scan_ip_for_open_ports(ip)
                    results_text.insert(tk.INSERT, f"Open ports: {open_ports}\n")
                    vulnerabilities = get_vulnerabilities_from_shodan(ip, open_ports)
                    for port, vulns in vulnerabilities.items():
                        results_text.insert(tk.INSERT, f"Port {port} vulnerabilities: {vulns}\n")
                        exploits = search_exploitdb(vulns)
                        for vuln, exploit_url in exploits.items():
                            results_text.insert(tk.INSERT, f"\t{vuln}: {exploit_url}\n")
    except FileNotFoundError:
        results_text.insert(tk.INSERT, f"File {ip_file} not found.\n")
    except Exception as e:
        results_text.insert(tk.INSERT, f"An error occurred: {e}\n")
        
        
def analyze_threaded():
    # Run the analysis in a separate thread to prevent GUI freezing
    analysis_thread = Thread(target=analyze_file_gui)
    analysis_thread.start()
    
    
    
def analyze_ip_gui():
    iptarget = Ip_entry.get()
    if not iptarget:
        results_text.insert(tk.INSERT, "Please insert an IP target to scan.\n")
        return
    progress_bar.start(2)
    IP = iptarget
    results_text.insert(tk.INSERT, f"Analyzing IP: {IP}\n---------------------------------\n")

    try:
        open_ports = scan_ip_for_open_ports(IP)
        results_text.insert(tk.INSERT, f"Open ports:\n")
        for port in open_ports:
            results_text.insert(tk.INSERT, f" - Port {port}\n")

        vulnerabilities = get_vulnerabilities_from_shodan(IP, open_ports)
        for port, vulns in vulnerabilities.items():
            results_text.insert(tk.INSERT, f"\nVulnerabilities for Port {port}:\n")
            if vulns:
                for vuln in vulns:
                    results_text.insert(tk.INSERT, f" - {vuln}\n")
                    exploits = search_exploitdb([vuln])
                    for exploit, url in exploits.items():
                        results_text.insert(tk.INSERT, f"   > Exploit: {exploit}, URL: {url}\n")
            else:
                results_text.insert(tk.INSERT, " - None found\n")
    except Exception as e:
        results_text.insert(tk.INSERT, f"An error occurred during analysis: {e}\n")
    finally:
        progress_bar.stop()



def analyze_threadedIPtarget():
    # Run the analysis in a separate thread to prevent GUI freezing
    analysis_thread = Thread(target=analyze_ip_gui)
    analysis_thread.start()
    

def ipinfo():
    ipinfotarget = Ip_entry.get()
    api = "http://ip-api.com/json/"
    
    #try:
    data = requests.get(api + ipinfotarget).json()
    if not ipinfotarget:
        results_text.insert(tk.INSERT, "Please insert a IP to get info on.\n")
        return
    if ipinfotarget:
        output = [
                "[Victim]: " + str(data.get('query', 'Unknown')),
                "[ISP]: " + str(data.get('isp', 'Unknown')),
                "[Organisation]: " + str(data.get('org', 'Unknown')),
                "[City]: " + str(data.get('city', 'Unknown')),
                "[Region]: " + str(data.get('region', 'Unknown')),
                "[Longitude]: " + str(data.get('lon', 'Unknown')),
                "[Latitude]: " + str(data.get('lat', 'Unknown')),
                "[Time zone]: " + str(data.get('timezone', 'Unknown')),
                "[Zip code]: " + str(data.get('zip', 'Unknown')),
        ]

        resultsipinfo = "\n".join(output)
        results_text.insert(tk.INSERT, resultsipinfo + "\n")    

    
        
def threadedipinfo():
    # Run the analysis in a separate thread to prevent GUI freezing
    analysis_thread = Thread(target=ipinfo)
    analysis_thread.start()   
    

def get_ip_website():
    domain = website_entry.get()
    try:
        # Get the IP address of the domain
        ip_address = socket.gethostbyname(domain)
        return results_text.insert(tk.INSERT, ip_address + "\n")
    except socket.gaierror as e:
        # Handle errors in case the domain is not found or other socket errors
        return f"Error getting IP for {domain}: {e}"

def threadedwebsiteipinfo():
    # Run the analysis in a separate thread to prevent GUI freezing
    analysis_thread = Thread(target=get_ip_website)
    analysis_thread.start()  

def clear_view():
    # Insert a large number of newlines to 'push' older content out of immediate view
    results_text.insert(tk.END, "\n" * 40)
    # Automatically scroll to the bottom of the widget
    results_text.see(tk.END)

def exitprogram():
    sys.exit()
    
    
# Set up the GUI
root = tk.Tk()
root.title("SpiderCrawler")
root.geometry("850x500")  # 800x600Set initial window size

# Make the window resizable
root.resizable(True, True)



ipframe = tk.Frame(root, padx=10, pady=10)
ipframe.pack(side=tk.TOP)
ipframe.pack(side=tk.LEFT)

Ip_name = tk.Label(ipframe, text="Ip Target:")
Ip_name.pack(side=tk.TOP)
Ip_name.pack(side=tk.LEFT, padx=10, pady=10)

Ip_entry = tk.Entry(ipframe, width=10)
Ip_entry.pack(side=tk.TOP)
Ip_entry.pack(side=tk.LEFT, padx=10, pady=10)




ipanalyze_button = tk.Button(ipframe, text="IPAnalyze", command=analyze_threadedIPtarget)
ipanalyze_button.pack(side=tk.BOTTOM)

ipinfo_button = tk.Button(ipframe, text="IPinfo", command=threadedipinfo)
ipinfo_button.pack(side=tk.BOTTOM)





websiteframe = tk.Frame(root, padx=10, pady=10)
websiteframe.pack(side=tk.TOP)

website_name = tk.Label(websiteframe, text="Domain:")
website_name.pack(side=tk.LEFT)

website_entry = tk.Entry(websiteframe, width=25)
website_entry.pack(side=tk.LEFT)

website_button = tk.Button(websiteframe, text="Find Domain IP", command=threadedwebsiteipinfo)
website_button.pack(side=tk.RIGHT)




fileframe = tk.Frame(root, padx=10, pady=10)
fileframe.pack(side=tk.TOP)

file_label = tk.Label(fileframe, text="File Path:")
file_label.pack(side=tk.LEFT)

file_entry = tk.Entry(fileframe, width=25)
file_entry.pack(side=tk.LEFT)
#file_entry.pack(side=tk.TOP)

browse_button = tk.Button(fileframe, text="Browse", command=select_file)
browse_button.pack(side=tk.LEFT)

analyze_button = tk.Button(fileframe, text="IPFileAnalyze", command=analyze_threaded)
analyze_button.pack(side=tk.BOTTOM)





resultsframe = tk.Frame(root, padx=10, pady=10)
resultsframe.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Initialize the progress bar
progress_bar = ttk.Progressbar(resultsframe, orient='horizontal', mode='indeterminate', length=280)
progress_bar.pack(side=tk.TOP, pady=10)

clear_button = tk.Button(resultsframe, text="Clear View", command=clear_view)
clear_button.pack(side=tk.LEFT)
clear_button.pack(side=tk.TOP)

exit_button = tk.Button(resultsframe, text="Exit/Cancel", command=exitprogram)
exit_button.pack(side=tk.RIGHT)
exit_button.pack(side=tk.TOP)

results_text = scrolledtext.ScrolledText(resultsframe, width=70, height=20)
results_text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
results_text.pack(side=tk.BOTTOM)


root.mainloop()

