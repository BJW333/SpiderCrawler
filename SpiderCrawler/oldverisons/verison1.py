import sys
import subprocess
from shodan import Shodan
import requests
#from msfconsole import MsfConsole
import tkinter as tk
import requests
from bs4 import BeautifulSoup
from tkinter import scrolledtext
from tkinter import filedialog
from threading import Thread
import socket
from tkinter import ttk
import webbrowser
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# Replace 'YOUR_SHODAN_API_KEY' with your actual Shodan API key
SHODAN_API_KEY = 'jxLW13mSmgc5PYI3kK1YqUXWvzGZXpbO'
shodan_api = Shodan(SHODAN_API_KEY)

global open_ports_list
open_ports_list = []   


# Command to open a new Terminal window and run the commands below
def display_open_ports_pie_chart(open_ports_list, results_frame):
    # Prepare data for the pie chart
    labels = open_ports_list
    sizes = [1 for _ in open_ports_list]  # Equal sizes for each port, adjust as needed
    # Create a figure and a set of subplots
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    # Embed the plot into the Tkinter GUI
    canvas = FigureCanvasTkAgg(fig, master=results_frame)  # Add this plot to the results frame
    canvas.draw()
    canvas.get_tk_widget().pack()

def show_open_ports_pie_chart():
    if not open_ports_list:  # Check if the list is empty or undefined
        print("No open ports data available. Please perform a scan first.")
        return
    # If data is available, display the pie chart
    display_open_ports_pie_chart(open_ports_list, resultsframe)
        
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


#may have to remove below method
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


#may have remove below method
#def analyze_ip(ip):
#    print(f"Analyzing IP: {ip}")
#    open_ports = scan_ip_for_open_ports(ip)
#    print(f"Open ports: {open_ports}")
#    vulnerabilities = get_vulnerabilities_from_shodan(ip, open_ports)
#    for port, vulns in vulnerabilities.items():
#       print(f"Port {port} vulnerabilities: {vulns}")
#        exploits = search_exploitdb(vulns)
#        for vuln, exploit_url in exploits.items():
#            print(f"\t{vuln}: {exploit_url}")



    
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
    
#global open_ports_list
#open_ports_list = []     
    
def analyze_ip_gui():
    #below global var new
    global open_ports_list
    iptarget = Ip_entry.get()
    if not iptarget:
        results_text.insert(tk.INSERT, "Please insert an IP target to scan.\n")
        return
    progress_bar.start(2)
    IP = iptarget
    results_text.insert(tk.INSERT, f"Analyzing IP: {IP}\n---------------------------------\n")

    try:
        #new line below
        open_ports_list = scan_ip_for_open_ports(IP)  # Use the global variable

        #old line below
        #open_ports = scan_ip_for_open_ports(IP)
        
        
        results_text.insert(tk.INSERT, f"Open ports:\n")
        #for port in open_ports:
        #    results_text.insert(tk.INSERT, f" - Port {port}\n")
            
        for port in open_ports_list:
            results_text.insert(tk.INSERT, f" - Port {port}\n")
        
        
        #display_open_ports_pie_chart(open_ports, resultsframe)
        
        #old line below
        #vulnerabilities = get_vulnerabilities_from_shodan(IP, open_ports)
        
        
        vulnerabilities = get_vulnerabilities_from_shodan(IP, open_ports_list)
        print(vulnerabilities)
        
        
        
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
        
    cve_ids = vulns
    #cve_ids = vulns
    process_cve_ids(cve_ids)







def get_cve_details(cve_id):
    """Fetches details for a given CVE identifier from the cve.circl.lu API."""
    api_url = f"https://cve.circl.lu/api/cve/{cve_id}"
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.json()
    else:
        results_text.insert(tk.INSERT, "\nFailed to retrieve CVE details. Please check the CVE ID and your internet connection.\n")
        return None

def display_exploit_details(cve_details):
    """Displays exploit details from the CVE information."""
    if cve_details is None:
        results_text.insert(tk.INSERT, "No details available to display.\n")
        return
    
    results_text.insert(tk.INSERT, "\n")
    results_text.insert(tk.INSERT, "\n")
    results_text.insert(tk.INSERT, "\n---------------------------------------------------------------------\n")
    results_text.insert(tk.INSERT, f"\nDetails for CVE: {cve_details.get('id')}\n")
    results_text.insert(tk.INSERT, "\n")
    results_text.insert(tk.INSERT, f"\nSummary: {cve_details.get('summary')}\n")
    results_text.insert(tk.INSERT, "\n---------------------------------------------------------------------\n")


    if 'references' in cve_details and cve_details['references']:
        results_text.insert(tk.INSERT, (""))
        results_text.insert(tk.INSERT, ("\nReferences:"))
        for ref in cve_details['references']:
            results_text.insert(tk.INSERT, f"\n{ref}\n") #could just me (ref)
    else:
        results_text.insert(tk.INSERT, ("\nNo references available.\n"))


def search_github_for_exploits(cve_id):
    """Searches GitHub for repositories related to the CVE ID."""
    results_text.insert(tk.INSERT, "\n")
    results_text.insert(tk.INSERT, "\n")
    results_text.insert(tk.INSERT, (f"\nSearching GitHub for potential exploits for {cve_id}...\n"))
    search_url = f"https://github.com/search?q={cve_id}+exploit&type=Repositories"
    results_text.insert(tk.INSERT, (f"\nCheck out GitHub search results at: {search_url}\n"))


def generate_google_search_query(cve_id):
    """Generates a Google search query for the user."""
    query = f"https://www.google.com/search?q={cve_id}+exploit"
    results_text.insert(tk.INSERT, (f"\nTo search for more exploit details on Google use this query: {query}\n"))
    results_text.insert(tk.INSERT, "\n---------------------------------------------------------------------\n")


def process_cve_ids(cve_ids):
    """Processes a list of CVE IDs."""
    for cve_id in cve_ids:
        print(f"Processing {cve_id}...")
        cve_details = get_cve_details(cve_id)
        display_exploit_details(cve_details)
        search_github_for_exploits(cve_id)
        generate_google_search_query(cve_id)



def analyze_threadedIPtarget():
    # Run the analysis in a separate thread to prevent GUI freezing
    analysis_thread = Thread(target=analyze_ip_gui)
    analysis_thread.start()
    findipcam()

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


def findipcam():
    ipcamip = Ip_entry.get()
    #webbrowser.open(f"http://{ipcamip}:80")
    results_text.insert(tk.INSERT, ("If an IP Cam exists it may be at this link") + "\n")
    ipcaminfolink1 = f"http://{ipcamip}:80"
    ipcaminfolink2 = f"http://{ipcamip}:443"
    ipcaminfolink3 = f"http://{ipcamip}:554"
    results_text.insert(tk.INSERT, ipcaminfolink1 + "\n")
    results_text.insert(tk.INSERT, ipcaminfolink2 + "\n")
    results_text.insert(tk.INSERT, ipcaminfolink3 + "\n")
    return results_text.insert(tk.INSERT, "\n")

    
    
def clear_view():
    # Insert a large number of newlines to 'push' older content out of immediate view
    results_text.insert(tk.END, "\n" * 40)
    # Automatically scroll to the bottom of the widget
    results_text.see(tk.END)

def exitprogram():
    sys.exit()
    
#http://128.95.77.59:80
    
# Set up the GUI
root = tk.Tk()
root.title("SpiderCrawler")

#overall size of program
root.geometry("950x750")  # 800x600Set initial window size

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

show_graph_button = tk.Button(ipframe, text="Show Ports Graph", command=show_open_ports_pie_chart)
show_graph_button.pack(side=tk.BOTTOM)



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

