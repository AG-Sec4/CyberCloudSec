import scapy.all as scapy

# Function to scan the network for devices
def scan(ip):
    # Create an ARP request with the given IP range
    arp_request = scapy.ARP(pdst=ip)
    
    # Create a broadcast Ethernet frame to send the ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the ARP request and Ethernet frame
    arp_request_broadcast = broadcast/arp_request
    
    # Send the ARP request and capture the response
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # Create an empty list to store the clients (IP and MAC addresses)
    clients_list = []
    
    # Parse the response to get the IP and MAC address of each device
    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    # Return the list of discovered devices
    return clients_list

# Function to print the results in a readable format
def print_result(result_list):
    print("IP Address\t\tMAC Address")
    print("----------------------------------------")
    for client in result_list:
        print(f"{client['ip']}\t\t{client['mac']}")

# Main function to ask for the IP range and start the scan
def main():
    # Ask the user for the IP range to scan
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1/24): ")
    
    # Run the network scan and store the results
    scan_result = scan(ip_range)
    
    # Print the results of the scan
    print_result(scan_result)

# Run the script
if __name__ == "__main__":
    main()
