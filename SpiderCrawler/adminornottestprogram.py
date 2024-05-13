import sys
import os
import ctypes
import subprocess

def is_admin():
    """Check if the program is running with administrative privileges."""
    try:
        if sys.platform == 'win32':
            # On Windows, check for admin rights
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # On macOS, check for root user
            return os.getuid() == 0
    except Exception as e:
        print(f"Error checking admin status: {e}")
        return False

def elevate_program():
    try:
        if sys.platform == 'win32':
            # For Windows, use ShellExecuteW to elevate privileges
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        else:
            # For macOS, use 'osascript' for a more native elevation prompt
            if not is_admin():
                script = 'do shell script "{}" with administrator privileges'.format(' '.join(['python3'] + sys.argv))
                subprocess.call(['osascript', '-e', script])
                sys.exit(0)
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")
        sys.exit(1)


#this be changed when incorpated with program
def main():
    """Main function that checks and elevates privileges if not admin."""
    if not is_admin():
        print("This program requires administrative privileges. Attempting to elevate...")
        elevate_program()
        sys.exit()

    print("Running with administrative privileges...")
    # Your main logic here

if __name__ == "__main__":
    main()
