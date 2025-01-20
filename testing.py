from colorama import init, Fore
import sys
import time

# Initialize colorama for colored output in the terminal
init(autoreset=True)

# Gradient color scheme for the ASCII title
def get_color_for_gradient(i, max_index):
    gradient_colors = [
        Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA
    ]
    color_index = int((i / max_index) * (len(gradient_colors) - 1))
    return gradient_colors[color_index]

# Function to print the gradient ASCII title
def print_gradient_ascii_title():
    title = r'''
██   ██  █████   ██████ ██   ██ ███████ ██████  ███    ███  █████  ████████ ███████
██   ██ ██   ██ ██      ██  ██  ██      ██   ██ ████  ████ ██   ██    ██    ██      
███████ ███████ ██      █████   █████   ██████  ██ ████ ██ ███████    ██    █████   
██   ██ ██   ██ ██      ██  ██  ██      ██   ██ ██  ██  ██ ██   ██    ██    ██      
██   ██ ██   ██  ██████ ██   ██ ███████ ██   ██ ██      ██ ██   ██    ██    ███████
    '''
    
    title_lines = title.split("\n")
    
    for y, line in enumerate(title_lines):
        max_line_length = len(line)
        
        for x, char in enumerate(line):
            if char != " ":
                color = get_color_for_gradient(x + y, max_line_length + len(title_lines))
                sys.stdout.write(color + char)
            else:
                sys.stdout.write(char)
        sys.stdout.write("\n")
        time.sleep(0.1)

# Call this function at the beginning to print the title whenever needed
def show_menu():
    print_gradient_ascii_title()  # Always prints the title first
    
# Main function or whenever you need to display the title
if __name__ == "__main__":
    show_menu()

from colorama import init, Fore
import os

# Initialize colorama for colored output in the terminal
init(autoreset=True)

# Function to print the centered message
def show_select_tool_message():
    message = "Please select a tool from the menu"
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen before showing the menu
    print(Fore.RED + message.center(100))  # Centering the message in the middle of the screen with red color

# Example menu display to check if the message works properly
def show_menu():
    show_select_tool_message()  # Displays the "Please select a tool from the menu" centered and in red
    print(Fore.GREEN + "1 [+] View System Information")
    print(Fore.GREEN + "2 [+] Run Network Tools (e.g., Nmap)")
    print(Fore.GREEN + "3 [+] Access File Manipulation Tools")
    print(Fore.GREEN + "4 [+] Start Web Penetration Testing")
    print(Fore.GREEN + "5 [+] Try Social Engineering Tools")
    print(Fore.GREEN + "6 [+] Launch Vulnerability Scanning")
    print(Fore.GREEN + "7 [+] Crack Passwords")
    print(Fore.GREEN + "8 [+] DNS and Subdomain Enumeration")
    print(Fore.GREEN + "9 [+] Perform Wi-Fi Cracking")
    print(Fore.GREEN + "10 [+] Conduct WAF Bypass Test")
    print(Fore.GREEN + "11 [+] Run Subdomain Scanning")
    print(Fore.GREEN + "12 [+] Start Malware Analysis")
    print(Fore.GREEN + "13 [+] Perform Cryptography (Encryption, Hashing)")
    print(Fore.GREEN + "14 [+] Sniff Network Traffic")
    print(Fore.GREEN + "15 [+] Keylogging (Educational Purposes)")
    print(Fore.GREEN + "16 [+] Run Command Injection Testing")
    print(Fore.GREEN + "17 [+] Remote Code Execution")
    print(Fore.GREEN + "18 [+] Perform Automated Web Scans")
    print(Fore.GREEN + "19 [+] Simulate DoS Attack")
    print(Fore.GREEN + "20 [+] Simulate Phishing Attack")
    print(Fore.GREEN + "21 [+] Run SQL Injection Test")
    print(Fore.GREEN + "22 [+] Simulate Reverse Shell")
    print(Fore.GREEN + "23 [+] Simulate RAT (Remote Access Trojan)")
    print(Fore.GREEN + "24 [+] Perform Port Forwarding")
    print(Fore.GREEN + "25 [+] Start Firewall Evasion Test")
    print(Fore.GREEN + "26 [+] Network Enumeration")
    print(Fore.RED + "27 [+] Exit HackingMate")

# Entry point of the program to check how the output looks
if __name__ == "__main__":
    show_menu()


import os
import subprocess
from colorama import init, Fore

init(autoreset=True)

# Function to display and execute tool based on selection
def show_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.RED + "HackerMate")
    print(Fore.RED + "=====================")
    print(Fore.YELLOW + "1. System Information")
    print(Fore.YELLOW + "2. Nmap (Network Scanning)")
    print(Fore.YELLOW + "3. File Manipulation")
    print(Fore.YELLOW + "4. Web Penetration Tool")
    print(Fore.YELLOW + "5. Social Engineering Tool")
    print(Fore.YELLOW + "6. Vulnerability Scanning")
    print(Fore.YELLOW + "7. Password Cracking")
    print(Fore.YELLOW + "8. DNS Subdomain Enumeration")
    print(Fore.YELLOW + "9. Wi-Fi Cracking")
    print(Fore.YELLOW + "10. WAF Bypass Testing")
    print(Fore.YELLOW + "11. Subdomain Scanning")
    print(Fore.YELLOW + "12. Malware Analysis")
    print(Fore.YELLOW + "13. Cryptography (Hashing)")
    choice = input(Fore.RED + "[+] Select a tool from the menu (1-13): ")

    if choice == "1":
        system_information_tool()
    elif choice == "2":
        nmap_tool()
    elif choice == "3":
        file_manipulation_tool()
    elif choice == "4":
        web_penetration_tool()
    elif choice == "5":
        social_engineering_tool()
    elif choice == "6":
        vulnerability_scanning_tool()
    elif choice == "7":
        password_cracking_tool()
    elif choice == "8":
        dns_subdomain_enumeration_tool()
    elif choice == "9":
        wifi_cracking_tool()
    elif choice == "10":
        waf_bypass_tool()
    elif choice == "11":
        subdomain_scanning_tool()
    elif choice == "12":
        malware_analysis_tool()
    elif choice == "13":
        cryptography_tool()
    else:
        print(Fore.RED + "[+] Invalid selection!")
        show_menu()

def install_tool(tool_name, install_command):
    print(Fore.RED + "[+] " + tool_name + " is not installed. To install it, follow these steps:")
    print(Fore.YELLOW + f"[+] For Ubuntu/Debian: {install_command['ubuntu']}")
    print(Fore.YELLOW + f"[+] For CentOS/RHEL: {install_command['centos']}")
    print(Fore.YELLOW + f"[+] For macOS: {install_command['macos']}")
    input(Fore.YELLOW + "[+] Press Enter to return to the main menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def system_information_tool():
    print(Fore.YELLOW + "[+] Retrieving System Information...")
    try:
        if os.name == "nt":
            os.system("systeminfo")
        else:
            os.system("uname -a")
    except Exception as e:
        print(Fore.RED + "[+] Error: Unable to retrieve system information.")
        install_tool("System Information", {'ubuntu': 'sudo apt install sysinfo', 'centos': 'sudo yum install sysinfo', 'macos': 'brew install sysinfo'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def nmap_tool():
    print(Fore.YELLOW + "[+] Running Nmap for network scanning...")
    try:
        ip_or_website = input(Fore.YELLOW + "[+] Enter an IP/Website to scan using Nmap: ")
        subprocess.run(f"nmap {ip_or_website}", check=True, shell=True)
    except subprocess.CalledProcessError:
        install_tool("Nmap", {'ubuntu': 'sudo apt-get install nmap', 'centos': 'sudo yum install nmap', 'macos': 'brew install nmap'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def file_manipulation_tool():
    print(Fore.YELLOW + "[+] Accessing File Manipulation Tools...")
    filename = input(Fore.YELLOW + "[+] Enter the filename to manipulate: ")
    choice = input(Fore.YELLOW + "[+] Choose an operation (1 - Read, 2 - Write, 3 - Delete): ")
    
    if choice == "1":
        try:
            with open(filename, 'r') as f:
                print(Fore.GREEN + f"[+] Contents of {filename}:")
                print(f.read())
        except FileNotFoundError:
            print(Fore.RED + f"[+] {filename} not found.")
    elif choice == "2":
        content = input(Fore.YELLOW + "[+] Enter content to write to the file: ")
        with open(filename, 'w') as f:
            f.write(content)
        print(Fore.GREEN + f"[+] Content written to {filename}.")
    elif choice == "3":
        os.remove(filename)
        print(Fore.RED + f"[+] {filename} deleted.")
    else:
        print(Fore.RED + "[+] Invalid choice.")
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def web_penetration_tool():
    print(Fore.YELLOW + "[+] Web Penetration Testing Tool...")
    website = input(Fore.YELLOW + "[+] Enter website to test (e.g., example.com): ")
    try:
        response = subprocess.check_output(["curl", "-I", website], stderr=subprocess.STDOUT)
        print(Fore.GREEN + f"[+] Headers for {website}:")
        print(response.decode())
    except Exception as e:
        print(Fore.RED + "[+] Error accessing website. Ensure curl is installed.")
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def social_engineering_tool():
    print(Fore.YELLOW + "[+] Social Engineering Tool...")
    email_subject = input(Fore.YELLOW + "[+] Enter email subject: ")
    email_body = input(Fore.YELLOW + "[+] Enter email body: ")
    print(Fore.GREEN + "[+] Social engineering email created:")
    print(Fore.GREEN + f"Subject: {email_subject}")
    print(Fore.GREEN + f"Body: {email_body}")
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def vulnerability_scanning_tool():
    print(Fore.YELLOW + "[+] Running Vulnerability Scan...")
    try:
        website = input(Fore.YELLOW + "[+] Enter website to scan for vulnerabilities: ")
        subprocess.run(f"nikto -h {website}", check=True, shell=True)
    except subprocess.CalledProcessError:
        install_tool("Nikto", {'ubuntu': 'sudo apt-get install nikto', 'centos': 'sudo yum install nikto', 'macos': 'brew install nikto'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def password_cracking_tool():
    print(Fore.YELLOW + "[+] Cracking Passwords...")
    hash_to_crack = input(Fore.YELLOW + "[+] Enter the hashed password to crack: ")
    subprocess.run(f"john --format=raw-md5 {hash_to_crack}", check=True, shell=True)
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def dns_subdomain_enumeration_tool():
    print(Fore.YELLOW + "[+] DNS and Subdomain Enumeration...")
    try:
        domain = input(Fore.YELLOW + "[+] Enter domain to enumerate subdomains: ")
        subprocess.run(f"sublist3r -d {domain}", check=True, shell=True)
    except subprocess.CalledProcessError:
        install_tool("Sublist3r", {'ubuntu': 'sudo apt install sublist3r', 'centos': 'sudo yum install sublist3r', 'macos': 'brew install sublist3r'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def wifi_cracking_tool():
    print(Fore.YELLOW + "[+] Performing Wi-Fi Cracking...")
    try:
        capture_file = input(Fore.YELLOW + "[+] Enter the capture file (e.g., handshake.cap): ")
        subprocess.run(f"aircrack-ng {capture_file}", check=True, shell=True)
    except subprocess.CalledProcessError:
        install_tool("Aircrack-ng", {'ubuntu': 'sudo apt install aircrack-ng', 'centos': 'sudo yum install aircrack-ng', 'macos': 'brew install aircrack-ng'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def waf_bypass_tool():
    print(Fore.YELLOW + "[+] Conducting WAF Bypass Test...")
    payload = input(Fore.YELLOW + "[+] Enter a payload to test WAF: ")
    print(Fore.GREEN + f"[+] Testing with payload: {payload}")
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def subdomain_scanning_tool():
    print(Fore.YELLOW + "[+] Subdomain Scanning...")
    try:
        domain = input(Fore.YELLOW + "[+] Enter domain to scan for subdomains: ")
        subprocess.run(f"sublist3r -d {domain}", check=True, shell=True)
    except subprocess.CalledProcessError:
        install_tool("Sublist3r", {'ubuntu': 'sudo apt install sublist3r', 'centos': 'sudo yum install sublist3r', 'macos': 'brew install sublist3r'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def malware_analysis_tool():
    print(Fore.YELLOW + "[+] Malware Analysis Tool...")
    file_path = input(Fore.YELLOW + "[+] Enter the path of the file to analyze: ")
    print(Fore.GREEN + f"[+] Running malware analysis on: {file_path}")
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def cryptography_tool():
    print(Fore.YELLOW + "[+] Cryptography (Encryption, Hashing) Tool...")
    password = input(Fore.YELLOW + "[+] Enter password to hash: ")
    hashed_password = subprocess.check_output(f"echo -n {password} | sha256sum", shell=True)
    print(Fore.GREEN + f"[+] Hashed Password (SHA256): {hashed_password.decode().strip()}")
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

# Start the application
show_menu()


import os
import subprocess
from colorama import init, Fore

init(autoreset=True)

# Function to display and execute tool based on selection
def show_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.RED + "HackerMate")
    print(Fore.RED + "=====================")
    print(Fore.YELLOW + "1. View System Information")
    print(Fore.YELLOW + "2. Run Network Tools (e.g., Nmap)")
    print(Fore.YELLOW + "3. Access File Manipulation Tools")
    print(Fore.YELLOW + "4. Start Web Penetration Testing")
    print(Fore.YELLOW + "5. Try Social Engineering Tools")
    print(Fore.YELLOW + "6. Launch Vulnerability Scanning")
    print(Fore.YELLOW + "7. Crack Passwords")
    print(Fore.YELLOW + "8. DNS and Subdomain Enumeration")
    print(Fore.YELLOW + "9. Perform Wi-Fi Cracking")
    print(Fore.YELLOW + "10. Conduct WAF Bypass Test")
    print(Fore.YELLOW + "11. Run Subdomain Scanning")
    print(Fore.YELLOW + "12. Start Malware Analysis")
    print(Fore.YELLOW + "13. Perform Cryptography (Encryption, Hashing)")
    print(Fore.YELLOW + "14. Sniff Network Traffic")
    print(Fore.YELLOW + "15. Keylogging (Educational Purposes)")
    print(Fore.YELLOW + "16. Run Command Injection Testing")
    print(Fore.YELLOW + "17. Remote Code Execution")
    print(Fore.YELLOW + "18. Perform Automated Web Scans")
    print(Fore.YELLOW + "19. Simulate DoS Attack")
    print(Fore.YELLOW + "20. Simulate Phishing Attack")
    print(Fore.YELLOW + "21. Run SQL Injection Test")
    print(Fore.YELLOW + "22. Simulate Reverse Shell")
    print(Fore.YELLOW + "23. Simulate RAT (Remote Access Trojan)")
    print(Fore.YELLOW + "24. Perform Port Forwarding")
    print(Fore.YELLOW + "25. Start Firewall Evasion Test")
    print(Fore.YELLOW + "26. Network Enumeration")
    print(Fore.RED + "27. Exit HackerMate")

    choice = input(Fore.RED + "[+] Select a tool from the menu (1-27): ")

    if choice == "1":
        system_information_tool()
    elif choice == "2":
        nmap_tool()
    elif choice == "3":
        file_manipulation_tool()
    elif choice == "4":
        web_penetration_tool()
    elif choice == "5":
        social_engineering_tool()
    elif choice == "6":
        vulnerability_scanning_tool()
    elif choice == "7":
        password_cracking_tool()
    elif choice == "8":
        dns_subdomain_enumeration_tool()
    elif choice == "9":
        wifi_cracking_tool()
    elif choice == "10":
        waf_bypass_tool()
    elif choice == "11":
        subdomain_scanning_tool()
    elif choice == "12":
        malware_analysis_tool()
    elif choice == "13":
        cryptography_tool()
    elif choice == "14":
        sniff_network_traffic_tool()
    elif choice == "15":
        keylogging_tool()
    elif choice == "16":
        command_injection_tool()
    elif choice == "17":
        remote_code_execution_tool()
    elif choice == "18":
        automated_web_scans_tool()
    elif choice == "19":
        dos_attack_tool()
    elif choice == "20":
        phishing_attack_tool()
    elif choice == "21":
        sql_injection_tool()
    elif choice == "22":
        reverse_shell_tool()
    elif choice == "23":
        rat_tool()
    elif choice == "24":
        port_forwarding_tool()
    elif choice == "25":
        firewall_evasion_tool()
    elif choice == "26":
        network_enumeration_tool()
    elif choice == "27":
        exit_tool()
    else:
        print(Fore.RED + "[+] Invalid selection!")
        show_menu()

# Additional functions for tools 14 to 27
def sniff_network_traffic_tool():
    print(Fore.YELLOW + "[+] Sniffing Network Traffic...")
    try:
        subprocess.run("tcpdump", check=True, shell=True)
    except subprocess.CalledProcessError:
        install_tool("Tcpdump", {'ubuntu': 'sudo apt-get install tcpdump', 'centos': 'sudo yum install tcpdump', 'macos': 'brew install tcpdump'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def keylogging_tool():
    print(Fore.YELLOW + "[+] Starting Keylogging Tool...")
    print(Fore.RED + "[!] Educational use only. Please be cautious.")
    # Implement your own keylogger functionality (or use a specific library)
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def command_injection_tool():
    print(Fore.YELLOW + "[+] Testing Command Injection...")
    try:
        user_input = input(Fore.YELLOW + "[+] Enter shell command to test injection: ")
        subprocess.run(user_input, check=True, shell=True)
    except subprocess.CalledProcessError:
        print(Fore.RED + "[+] Error executing command.")
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def remote_code_execution_tool():
    print(Fore.YELLOW + "[+] Attempting Remote Code Execution...")
    # Implement functionality here (e.g., using RCE testing scripts)
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def automated_web_scans_tool():
    print(Fore.YELLOW + "[+] Performing Automated Web Scans...")
    try:
        website = input(Fore.YELLOW + "[+] Enter a website URL to scan: ")
        subprocess.run(f"w3af_console -s {website}", check=True, shell=True)
    except subprocess.CalledProcessError:
        install_tool("w3af", {'ubuntu': 'sudo apt-get install w3af', 'centos': 'sudo yum install w3af', 'macos': 'brew install w3af'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def dos_attack_tool():
    print(Fore.YELLOW + "[+] Simulating DoS Attack...")
    # Implement DoS attack logic (e.g., using LOIC)
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def phishing_attack_tool():
    print(Fore.YELLOW + "[+] Simulating Phishing Attack...")
    # Implement phishing attack logic (e.g., using social engineering toolkit)
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def sql_injection_tool():
    print(Fore.YELLOW + "[+] Running SQL Injection Test...")
    website = input(Fore.YELLOW + "[+] Enter website URL for SQL injection: ")
    try:
        subprocess.run(f"sqlmap -u {website}", check=True, shell=True)
    except subprocess.CalledProcessError:
        install_tool("SQLmap", {'ubuntu': 'sudo apt-get install sqlmap', 'centos': 'sudo yum install sqlmap', 'macos': 'brew install sqlmap'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def reverse_shell_tool():
    print(Fore.YELLOW + "[+] Simulating Reverse Shell...")
    # Implement reverse shell simulation
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def rat_tool():
    print(Fore.YELLOW + "[+] Simulating RAT (Remote Access Trojan)...")
    # Implement RAT (e.g., create a simple listener)
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def port_forwarding_tool():
    print(Fore.YELLOW + "[+] Performing Port Forwarding...")
    # Implement port forwarding functionality
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def firewall_evasion_tool():
    print(Fore.YELLOW + "[+] Conducting Firewall Evasion Test...")
    # Implement firewall evasion logic
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls ' if os.name == 'nt' else 'clear')
    show_menu()

def network_enumeration_tool():
    print(Fore.YELLOW + "[+] Running Network Enumeration...")
    try:
        network = input(Fore.YELLOW + "[+] Enter network to scan (e.g., 192.168.1.0/24): ")
        subprocess.run(f"nmap -sP {network}", check=True, shell=True)
    except subprocess.CalledProcessError:
        install_tool("Nmap", {'ubuntu': 'sudo apt-get install nmap', 'centos': 'sudo yum install nmap', 'macos': 'brew install nmap'})
    input(Fore.YELLOW + "[+] Press Enter to return to the menu.")
    os.system('cls' if os.name == 'nt' else 'clear')
    show_menu()

def exit_tool():
    print(Fore.GREEN + "[+] Exiting HackerMate...")
    exit()

# Start the application
show_menu()
