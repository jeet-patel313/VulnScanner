import portscanner

targets_ip = input("[+] * Enter target to scan for vulnerable open ports: ")
port_number = int(input("[+] * Enter amount of ports you want to scan(100 - first 100 ports): "))
vuln_file = input("[+] * Enter path to the file with vulnerable softwares: ")
print("\n")

target = portscanner.PortScan(targets_ip, port_number)
target.scan()

with open(vuln_file, 'r') as file:	#open file in read mode
	count = 0
	for banner in target.banners:
		file.seek(0)
		for line in file.readlines():
			if line.strip() in banner:
				print('[!!] VULNERABLE BANNER "' + banner + '" ON PORT: ' + str(target.open_ports[count]))
		count += 1

