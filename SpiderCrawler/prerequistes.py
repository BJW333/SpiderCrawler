import subprocess
import sys

def is_command_available(command):
    """Check if a command is available on the system's path."""
    try:
        subprocess.run([command, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def install_searchsploit_mac():
    """Install searchsploit on macOS using Homebrew."""
    if not is_command_available('brew'):
        print("Installing Homebrew...")
        subprocess.run('/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"', shell=True)
    print("Installing searchsploit...")
    subprocess.run(['brew', 'install', 'exploitdb'], check=True)

def install_searchsploit_windows():
    """Guide the user to install Docker and pull the exploitdb image on Windows."""
    if not is_command_available('docker'):
        print("Please install Docker from https://www.docker.com/ and rerun this script.")
        sys.exit(1)
    print("Pulling the exploitdb image from Docker Hub...")
    subprocess.run(['docker', 'pull', 'offensivesecurity/exploitdb'], check=True)

def setup_searchsploit():
    """Setup searchsploit based on the OS."""
    if sys.platform.startswith('darwin'):
        if is_command_available('searchsploit'):
            subprocess.run(['searchsploit', '-u'])
            print("searchsploit is already installed and updated.")
        else:
            install_searchsploit_mac()
    elif sys.platform.startswith('win32'):
        install_searchsploit_windows()
    else:
        print("Unsupported OS. Please run this script on macOS or Windows.")

setup_searchsploit()
