import nmap

scanner = nmap.PortScanner()

print("Welcome! This is a simple nmap automation tool \n")

ip_addr = input("Please enter the ip address you want to scan: ")

print("The IP addr you entered is: ", ip_addr)

type(ip_addr) #input will be sanitized to verify the rght input is entered

# response user gives when asked what scan they want to run 

resp = input(""" \nPlease enter the type of scan you want to run 
                   1) SYN ACK Scan
                   2) UDP Scan
                   3) Comprehensive Scan \n""")

# print("You have selected option: ", resp)

if resp == '1':
    # first print 
    print("Nmap version: ", scanner.nmap_version())

    # initialize scanner - call nmap class by providing arguements to perform the type of scan selected
    # scanner.scan(ip address, range of ports, type of scan)
    scanner.scan(ip_addr, '1-1024', '-v -sS')

    print(scanner.scaninfo())

    # tells user if the ip address is online or offline
    print("IP status: ", scanner[ip_addr].state())

    # print all protocols
    print(scanner[ip_addr].all_protocols())

    # display all open ports with keys method - keys returns all active ports
    print("Open ports: ", scanner[ip_addr]['tcp'].keys())