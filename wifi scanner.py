# Import scapy
import scapy.all as scapy
# The socket module in Python is an interface to the Berkeley sockets API.
import socket
# method to see if we can instantiate a valid ip address to test.
import ipaddress
import nmap


# We need to create regular expressions to ensure that the input is correctly formatted.
import re


# Basic user interface header
print(r"""
 __  __      _                   _    
|  \/  |_ __(_) __ _  __ _ _ __ | | __
| |\/| | '__| |/ _` |/ _` | '_ \| |/ /
| |  | | |  | | (_| | (_| | | | |   < 
|_|  |_|_|  |_|\__, |\__,_|_| |_|_|\_\
               |___/                  
""")
print("Enter your choice")
print("1 For lan device scanner")
print("2 For port scanner using sockets")
print("3 For port scanner using nmap")
choice =int(input())

if choice==1:
    # Regular Expression Pattern to recognise IPv4 addresses.
    ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")

    # Get the address range to ARP
    while True:
        ip_add_range_entered = input("\nPlease enter the ip address and range that you want to send the ARP request to (ex 192.168.1.0/24): ")
        if ip_add_range_pattern.search(ip_add_range_entered):
            print(f"{ip_add_range_entered} is a valid ip address range")
            break


    # Try ARPing the ip address range supplied by the user. 
    # The arping() method in scapy creates a pakcet with an ARP message 
    # and sends it to the broadcast mac address ff:ff:ff:ff:ff:ff.
    # If a valid ip address range was supplied the program will return 
    # the list of all results.
    arp_result = scapy.arping(ip_add_range_entered)

elif choice == 2:
    # Regular Expression Pattern to extract the number of ports you want to scan. 
    # You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    # Initialising the port numbers, will be using the variables later on.
    port_min = 0
    port_max = 65535

    # This script uses the socket api to see if you can connect to a port on a specified ip address. 
    # Once you've successfully connected a port is seen as open.
    # This script does not discriminate the difference between filtered and closed ports.
    open_ports = []
    # Ask user to input the ip address they want to scan.
    while True:
        ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")
        # If we enter an invalid ip address the try except block will go to the except block and say you entered an invalid ip address.
        try:
            ip_address_obj = ipaddress.ip_address(ip_add_entered)
            # The following line will only execute if the ip is valid.
            print("You entered a valid ip address.")
            break
        except:
            print("You entered an invalid ip address")
        

    while True:
        # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning all
        # the ports is not advised.
        print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
        port_range = input("Enter port range: ")
        # We pass the port numbers in by removing extra spaces that people sometimes enter. 
        # So if you enter 80 - 90 instead of 80-90 the program will still work.
        port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
        if port_range_valid:
            # We're extracting the low end of the port scanner range the user want to scan.
            port_min = int(port_range_valid.group(1))
            # We're extracting the upper end of the port scanner range the user want to scan.
            port_max = int(port_range_valid.group(2))
            break

    # Basic socket port scanning
    for port in range(port_min, port_max + 1):
        # Connect to socket of target machine. We need the ip address and the port number we want to connect to.
        try:
            # Create a socket object
            # You can create a socket connection similar to opening a file in Python. 
            # We can change the code to allow for domain names as well.
            # With socket.AF_INET you can enter either a domain name or an ip address 
            # and it will then continue with the connection.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # You want to set a timeout for the socket to try and connect to the server. 
                # If you make the duration longer it will return better results. 
                # We put it at 0.5s. So for every port it scans it will allow 0.5s 
                # for a successful connection.
                s.settimeout(0.5)
                # We use the socket object we created to connect to the ip address we entered and the port number. 
                # If it can't connect to this socket it will cause an exception and the open_ports list will not 
                # append the value.
                s.connect((ip_add_entered, port))
                # If the following line runs then then it was successful in connecting to the port.
                open_ports.append(port)

        except:
            # We don't need to do anything here. If we were interested in the closed ports we'd put something here.
            pass

    # We only care about the open ports.
    for port in open_ports:
        # We use an f string to easily format the string with variables so we don't have to do concatenation.
        print(f"Port {port} is open on {ip_add_entered}.")
elif choice == 3:
    # Regular Expression Pattern to recognise IPv4 addresses.
    ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    # Regular Expression Pattern to extract the number of ports you want to scan. 
    # You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    # Initialising the port numbers, will be using the variables later on.
    port_min = 0
    port_max = 65535

    # This port scanner uses the Python nmap module.
    # You'll need to install the following to get it work on Linux:
    # Step 1: sudo apt install python3-pip
    # Step 2: pip install python-nmap
    open_ports = []
    # Ask user to input the ip address they want to scan.
    while True:
        ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")
        if ip_add_pattern.search(ip_add_entered):
            print(f"{ip_add_entered} is a valid ip address")
            break

    while True:
        # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning 
        # all the ports is not advised.
        print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
        port_range = input("Enter port range: ")
        port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
        if port_range_valid:
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            break

    nm = nmap.PortScanner()
    # We're looping over all of the ports in the specified range.
    for port in range(port_min, port_max + 1):
        try:
            # The result is quite interesting to look at. You may want to inspect the dictionary it returns. 
            # It contains what was sent to the command line in addition to the port status we're after. 
            # For in nmap for port 80 and ip 10.0.0.2 you'd run: nmap -oX - -p 89 -sV 10.0.0.2
            result = nm.scan(ip_add_entered, str(port))
            # Uncomment following line and look at dictionary
            # print(result)
            # We extract the port status from the returned object
            port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
            print(f"Port {port} is {port_status}")
        except:
            # We cannot scan some ports and this ensures the program doesn't crash when we try to scan them.
            print(f"Cannot scan port {port}.")
else:
    print("Wrong choice")
