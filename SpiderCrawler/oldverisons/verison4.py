import tkinter as tk
from tkinter import BooleanVar, Label, Checkbutton, Radiobutton, Button, Entry, Frame

def execute_nmap():
    """Assembles and displays the Nmap command based on selected options."""
    ip = ip_entry.get()
    if not ip:
        print("Please enter a target IP or hostname.")
        return

    cmd = ['nmap']
    if options['fast_scan'].get():
        cmd.append('-F')
    if options['show_open'].get():
        cmd.append('--open')
    if options['version_detection'].get():
        cmd.append('-sV')
    if options['os_detection'].get():
        cmd.append('-O')
    if options['script_scan'].get():
        cmd.append('-sC')

    cmd.append('-T' + timing.get())
    cmd.append(ip)

    # Display command for review (or execute it using subprocess in a real scenario)
    print("Nmap Command to Execute:")
    print(' '.join(cmd))

# Setup the main window
root = tk.Tk()
root.title("Nmap Scan Configuration")
root.geometry("500x300")

# Variables to hold the checkbox states
options = {
    'fast_scan': BooleanVar(value=False),
    'show_open': BooleanVar(value=False),
    'version_detection': BooleanVar(value=False),
    'os_detection': BooleanVar(value=False),
    'script_scan': BooleanVar(value=False)
}
timing = tk.StringVar(value="T4")  # Default timing is T4

# Frame for Scan Options
options_frame = Frame(root)
options_frame.pack(pady=20)

# Checkboxes for different scanning options
Checkbutton(options_frame, text="Fast Scan (Most Common Ports): -F ", var=options['fast_scan']).pack(anchor='w')
Checkbutton(options_frame, text="Show Only Open Ports: --open ", var=options['show_open']).pack(anchor='w')
Checkbutton(options_frame, text="Version Detection: -sV ", var=options['version_detection']).pack(anchor='w')
Checkbutton(options_frame, text="OS Detection: -O ", var=options['os_detection']).pack(anchor='w')
Checkbutton(options_frame, text="Script Scan (Default Scripts): -sC ", var=options['script_scan']).pack(anchor='w')

# Timing options using radio buttons
Label(options_frame, text="Timing Template:").pack(anchor='w')
for t in ['T2', 'T3', 'T4', 'T5']:
    Radiobutton(options_frame, text=t, value=t, variable=timing).pack(anchor='w')

# Entry for IP or hostname
ip_entry = Entry(root, width=30)
ip_entry.pack(pady=20)

# Button to execute Nmap
Button(root, text="Generate Nmap Command", command=execute_nmap).pack(pady=20)

# Start the Tkinter event loop
root.mainloop()



