import nmap
import socket
s = socket.socket()
scanner = nmap.PortScanner()
print("Welcome to simple nmap tool")
print("-"*50)

ip_address = input("Enter the ip address of target: ")
print("The ip you entered is " , ip_address)
type(ip_address)

response = input("""\nEnter the type of scan
		    1)SYN ACK Scan
		    2)UDP Scan
		    3)Comprehensive Scan\n""")

print("You select the option \n" , response)

if response =='1' :
	print("Nmap Version :" , scanner.nmap_version())
	scanner.scan(ip_address , '1-1024' , '-v  -sS')	
	print(scanner.scaninfo())
	print("ip status : " , scanner[ip_address].state())
	print(scanner[ip_address].all_protocols())
	print("open ports" , s.connect(ip_address , int(scanner[ip_address]['tcp'].keys())))

	print(s.recv(1024))
	
elif response =='2' :
	print("Nmap Version :" , scanner.nmap_version())
	scanner.scan(ip_address , '1-1024' , '-v  -sU')	
	print(scanner.scaninfo())
	print("ip status : " , scanner[ip_address].state())
	print(scanner[ip_address].all_protocols())
	print("open ports" , scanner[ip_address]['udp'].keys())
	
elif response =='3':
	print("Nmap Version :" , scanner.nmap_version())
	scanner.scan(ip_address , '1-1024' , '-v -sS -sV -A -O')
	print(scanner.scaninfo())
	print("ip status :" , scanner[ip_address].state())
	print(scanner[ip_address].all_protocols())
	print("open ports" , scanner[ip_address]['tcp'].keys())
	
else :
	print("Enter the invalid option")
