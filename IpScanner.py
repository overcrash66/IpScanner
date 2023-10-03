import os
import re
import sys
import socket
import json
import time
import urllib3
from lxml import etree
import subprocess
import threading
import signal
import requests
from queue import Queue
import datetime
from pyfiglet import Figlet
import random

def generate_overcrash_art():
	custom_fig = Figlet(font='slant')
	colors = ['red', 'green', 'yellow', 'blue', 'purple', 'cyan', 'white']

	for _ in range(3):	# Repeat the animation 3 times
		for color in colors:
			colored_text = f"\033[1;{random.randint(30, 37)}m{color}\033[0m"
			ascii_art = custom_fig.renderText("Welcome to OC66 Network Tool")
			colored_ascii_art = ascii_art.replace("Welcome to OC66 Network Tool", colored_text + "Welcome to OC66 Network Tool" + "\033[0m")
			
			print(colored_ascii_art)
			time.sleep(0.2)
			# Clear the console for the next frame
			print('\033c', end='')

generate_overcrash_art()

def signal_handler(sig, frame):
	print('You pressed Ctrl+C!')
	get_menu_choice()

signal.signal(signal.SIGINT, signal_handler)

# Menu 1: IP/Domain Geolocation - tested Pass
def geolocate_ip():
	try:
		ip_or_domain = input("Please enter IP or Domain Address to Geo locate: ")
		
		if ip_or_domain == '127.0.0.1' or ip_or_domain == 'localhost':
			print("Cannot scan localhost ip ! please use WAN IP address .")
			geolocate_ip()

		query_url = re.match("^(http[s]?://)?([a-z0-9.]{1,})[/]?([a-z]{1,})?(/.*)?$", ip_or_domain)

		if query_url:
			query_address = query_url.group(2)
			try:
				query_ip = socket.gethostbyname(query_address)
			except:
				print("Invalid Address")
				time.sleep(4)
				geolocate_ip()
	except:
		get_menu_choice()

	try:
		query_ip
	except:
		if re.match("^(([1]?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}([1]?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))$", ip_or_domain):
			query_ip = ip_or_domain
		else:
			print("Invalid IP Address")
			time.sleep(4)
			geolocate_ip()
	else:
		#ip_info_array = ipInfoFetch(query_ip)
		ip_info_array = []
		if len(ip_info_array) == 0:
			ip_info_array = ipInfoFetch(query_ip)
		if not ip_info_array:
			print("Unable to Check IP Address, try again later")
			geolocate_ip()

		print(f"IP: {ip_info_array[0]}\nHosted by: {ip_info_array[1]}\nCity: {ip_info_array[2]}\nCountry: {ip_info_array[3]}")
		time.sleep(4)
		get_menu_choice()

# Search funcion using geoipfetch.net and/or ip-api.com
def ipInfoFetch(query_ip):
	ipDataArray = []
	utf8_parser = etree.XMLParser(encoding='utf-8')
	geoIpLookupUrl = 'http://api.geoiplookup.net/?query=' + query_ip
	ipApiUrl = 'http://ip-api.com/json/' + query_ip
	http = urllib3.PoolManager()
	geoIpRequest = http.request('GET', geoIpLookupUrl, preload_content=False)
	if geoIpRequest.status == 200:
		geoIpXmlFile = geoIpRequest.read()
		geoIpXml = etree.fromstring(geoIpXmlFile, parser=utf8_parser)
		ipDataArray.append(geoIpXml[0][0][0].text)
		ipDataArray.append(geoIpXml[0][0][2].text)
		ipDataArray.append(geoIpXml[0][0][3].text)
		ipDataArray.append(geoIpXml[0][0][5].text)
	else:
		ipApiRequest = http.request('GET', ipApiUrl, preload_content=False)
		if ipApiRequest.status == 200:
			ipApiJson = json.load(ipApiRequest)
			ipDataArray.append(ipApiJson["query"])
			ipDataArray.append(ipApiJson["isp"])
			ipDataArray.append(ipApiJson["city"])
			ipDataArray.append(ipApiJson["country"])

	return ipDataArray

# Menu 2: IP Traffic Logger -  Tested Pass
def ip_traffic_logger():
	print('$' * 15 + '	IP TRAFFIC LOGGER ' + '$' * 15)

	# nothing = input('<Press enter to start scanning>')  # wait for user input
	running = 1	 # parameter which controls below while loop
	scannum = 1	 # parameter which counts how many scan logs have been printed
	first_run = 1
	Unique_LIST = []  # list of unique strings <outgoing_ip>_<PID>_<process_name> from processes

	def timeouttest(api1T, api2T, timeout_input, echo_text):  # timeout and connection test to see if API are available
		api1T = 0
		api2T = 0
		if echo_text == 1:
			print('\t Performing connection test for API .....')
			print('\t	[geo-location of ip-address]')
		try:  # test timeout on main ip-detail grab api [best]
			r = requests.get('http://ip-api.com/', timeout=timeout_input)  # limited to 1000 IP lookups in a day for free account
		except requests.Timeout:
			api1T = 1
		except:
			api1T = 1
		try:  # test timeout on secondary ip-detail grab api
			r = requests.get('https://ipapi.co/', timeout=timeout_input)  # limited to 1000 IP lookups in a day for free account
		except requests.Timeout:
			api2T = 1
		except:
			api2T = 1
		if echo_text == 1:
			print('\t ...Test complete!\n')
		return api1T, api2T

	# Exclud_process = []
	api1_timeout = 0
	api2_timeout = 0

	# MAIN SECTION OF CODE [CONTINUOUS SCANNING until program close or error]
	while running == 1:
		try:
			api_connect_attempt = 0
			api_timeout_persist = 0
			profilesNEW = []
			
			k = subprocess.Popen(['netstat', '-ano'], stdout=subprocess.PIPE)
			output_bytes, _ = k.communicate()
			output_str = output_bytes.decode('utf-8')
			#profilesNEW = re.findall(r'(.+?) +(\d+\.\d+\.\d+\.\d+:\d+) +(\d+\.\d+\.\d+\.\d+:\d+) +(.+?)\r', output_str, flags=re.DOTALL)

			profilesNEW = re.findall(r'\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+:\d+)\s+(\d+\.\d+\.\d+\.\d+:\d+)\s+(.*?)\s*\r', output_str, flags=re.DOTALL)

			if profilesNEW:
				print("Scanned IP Connections:")
				#for profile in profilesNEW:
				#	print(f"  {profile[1]} -> {profile[2]} (PID: {profile[0]}, Process: {profile[3]})")
			else:
				print("No established connections found.")
				get_menu_choice()


			tasks = []	# initialize (empty) list of task names picked up in scan
			now = datetime.datetime.now()  # current date and time
			tasks = os.popen("tasklist").readlines()  # get list of processes detected as currently running (cmd)
			del tasks[0]  # removes (deletes) first row from "tasks" (which is just a blank line)
			del tasks[0]  # removes (deletes) next row from "tasks" (which is just column headers of output from tasklist command)
			del tasks[0]  # removes (deletes) next row from "tasks" (which is separator of column header from data in columns)
			#del tasks[0]
			# final "tasks" is just tasklist data; image name
			# [below] cur=parameter which keeps track of the current process being separated into distinct data (start cur=0)
			for cur, x in enumerate(tasks, start=0):  # enumerate through each element of "tasks"
				tasks[cur] = tasks[cur].split()	 # split each element (sentence) of "tasks" into distinct element
			r = []	# initialize list of established connections which will be complete collection of imname,PID, out/in IP etc... (for each process)
			y = []	# initialize list which will be a collection of ip addresses and PID which has made "established connection
			for x in profilesNEW:  # iterate through each element of "profilesNEW" (which are a list of tasks with established connection to an external ip)
				# each x has the form  ('  TCP	  192.168.0.18:54914	 54.230.245.51:443		', '	 5548')
				# which is		  (' {con. type} {ingoing ip}:{port} {outgoing ip}:{port}	', '	PID ')
				y = x[0] + x[1]	 # y is =(' {con. type} {ingoing ip}:{port} {outgoing ip}:{port}  PID')
				y = y.split()  # get elements of y which are distinct by separation of ' ' that is y=[{con. type},{ingoing ip}:{port},{outgoing ip}:{port},PID]
				y[1] = y[1].split(':')[0]  # y[1]={ingoing ip}	(remove ":{port}")
				y[2] = y[2].split(':')[0]  # y[2]={outgoing ip}	  (remove ":{port}")
				# y is now =[{con. type},{ingoing ip},{outgoing ip},PID]
				pf = 0	# parameter which indicates if at least one PID of "tasks"
				for z in tasks:	 # for each row, z= imagename,PID, etc... for "tasks"
					if z[1] in y[3] and '.exe' in z[0]:	 # if PID z[1] in PID of y and is the image name is .exe (not something else due to error)
						y.append(z[0])	# append the image name to the related y (by PID between tasks and y)
						pf = 1	# set the parameter to 1 which indicates at least one "Established" connection has been found
				if pf == 0:	 # if not at least one relation of PID between tasks and y
					y.append('Process Unknown/dead')  # append a string that 'process is dead/unknown' (used later in code)
				r.append(y)	 # append final y to r (data in y was found to have a relation to a running process listed in "tasks")
			newscan = 0	 # initialize parameter which, if =1, indicates at least one new establish ip connection and currently running process has been found
			nw = []	 # list of these new processes
			for x in r:	 # for each element of r (list of running processes (PID, imname, ip) with an established connection)
				if x[2] + '_' + x[3] + '_' + x[4] not in Unique_LIST and x[2] != '127.0.0.1':  # if this element of r has PID or image name (process name) unique to previously logged establish connections
					nw.append(x)  # append to the list of unique establish processes
					Unique_LIST.append(x[2] + '_' + x[3] + '_' + x[4])	# add <outgoing_ip>_<PID>_<process_name> to unique list
					newscan = 1	 # set newscan parameter to 1 to indicate a new printout of at least one unique established process will be printed
			if newscan == 1:  # if new scan = 1 [if newscan=0, no new log is to printed and "while loop" starts again with a new scan]
				# Exclud_process, txtfile_err = process_exclude_obtain(Exclud_process, txtfile_err, 1)	# re-read text-file to see if new excludes added
				print('Scan number ' + str(scannum) + ':')	 # indicate the number of scan log being printed
				print(' time performed: ' + str(now) + '\n')  # indicate the time that this scan was performed at (will be give or take ~10 seconds)
				api1_timeout, api2_timeout = timeouttest(api1_timeout, api2_timeout, 2, 0)	# timeoutctest
				print(' Internal IP || Foreign IP (country,state;city - organisation) || PID || Process name')	# header names of printed data
				for x in nw:  # for each element of the list of newly established (connect) processes to be logged
					if api1_timeout == 0:  # if the primary API did not time out
						try:  # try to obtain the country, state, city of outgoing (foreign) ip address [if error, go to "catch"]
							ip_details = urllib.request.urlopen('http://ip-api.com/csv/' + x[2]).read().split(',')	# read html of ip details from the website
							country = ip_details[1]	 # record the country name related to the foreign ip address
							state = ip_details[3]  # record the state name related to the foreign ip address
							city = ip_details[5]  # record the city name related to the foreign ip address
							org = ip_details[11]  # record the organization name related to the foreign ip address
						except:	 # if an error occurred with recording details of interest in "try:"
							if x[2] in '127.0.0.1':	 # assess whether the "foreign" ip is just a local (internal) ip address
								country = 'local_host'	# set the "country name"
								state = '[internal]'  # set the "sity name"
								city = ''  # leave the city name blank
								org = ''
							else:  # else if country, state, city could not be obtained (for other circumstances)
								country = 'N/A'	 # set the country name to 'N/A' ('Not available)
								state = ''	# leave the state name blank
								city = ''  # leave the city name blank
								org = ''
					else:  # if the primary API timed out
						if api2_timeout == 0:  # if the secondary API did not time out
							country = ''
							state = ''
							city = ''
							org = ''
							if x[2] in '127.0.0.1':	 # assess whether the "foreign" ip is just a local (internal) ip address
								country = 'local_host'	# set the "country name"
								state = '[internal]'  # set the "sity name"
								city = ''  # leave the city name blank
								org = ''
							else:  # else if country, state, city could not be obtained (for other circumstances)
								try:
									ip_details = urllib.request.urlopen('https://ipapi.co/' + x[2] + '/csv/').read().split('\r\n')[1]
									country = ip_details[5]	 # record the country name related to the foreign ip address
									state = ip_details[3]  # record the state name related to the foreign ip address
									city = ip_details[1]  # record the city name related to the foreign ip address
									org = ip_details[12]  # record the organization name related to the foreign ip address
								except:
									country = 'N/A'
									state = 'N/A'
									city = 'N/A'
									org = 'N/A'
						else:
							country = 'N/A'
							state = 'N/A'
							city = 'N/A'
							org = 'N/A'
							if api_connect_attempt < 5:	 # if 5 or more consecutive timeouts for all APIs / skip connect test on the current scan to save time
								api1_timeout, api2_timeout = timeouttest(api1_timeout, api2_timeout, 1, 0)	# timeout test
								if api1_timeout == 1 and api2_timeout == 1:
									api_connect_attempt += 1
								else:
									api_connect_attempt = 0
							else:
								api_timeout_persist = 1
					print(x[1] + ' || ' + x[2] + '(' + country + ',' + state + ';' + city + '-' + org + ') || ' + x[3] + ' || ' + x[4])
					# (above) print; Internal IP + Foreign IP (country, state; city) + PID + Process name
				#print('######################################################################\n')
				if api_timeout_persist == 1:  # if API timeout persistent
					print('\n Both APIs used to obtain locational data for ip-addresses were found to')
					print('have persistent time-out issues on this scan (note: requires an internet connection)\n')
				print('ACTIVELY SCANNING, NEW RESULTS WILL BE DISPLAYED.......')
				# get_menu_choice()
				# scannum += 1	# update parameter which indicates a new scanlog has just been printed (count of logs printed)
				# running = 0
				# Exclud_process, txtfile_err = process_exclude_obtain(Exclud_process, txtfile_err, 1)	# re-read text-file to see if new excludes added
		except Exception as er2:  # If an error was experienced in the main code section
			running = 0	 # above (related error is recorded as 'er2') and while loop param (running) set 0 to break scanning
			print(str(er2))
			get_menu_choice()
			#exit()

# Menu 3: Scan Running Processes - Tested Pass
def scan_running_processes():
	while True:
		try:
			u=subprocess.Popen(["netstat","-n"], stdout=subprocess.PIPE, shell=True).stdout.read().splitlines()	 # retrieve input
			for x in range(4, len(u)):	# First 4 lines are rubbish
				p = len(u[x])-11  # Eliminates state and most whitespace
				ipaddr, port = str(u[x])[32:p].strip().split(":")  # First 33 are other crap, strip removes whitespace, split removes ":" + makes variables
				time.sleep(1)
				if ipaddr != "127.0.0.1":
					# print("Please wait i need to scan your network")
					place = region(ipaddr)	# Find country
					# k=requests.get("http://ip-api.com/json/"+a).json()["country"];
					print("=======================================================")
					print("IP: {0} \nplace: {1} \nPort: {2}".format(ipaddr, place, port))  # print
					print("===============Press Ctrl+C to stop Scan===============")
				else:
					print("=======================================================")
					print("N/A -- This is a Local Process Not connected to WAN")
					print("Using Port: {0}".format(port))  # print
					print("===============Press Ctrl+C to stop Scan===============")
					# time.sleep(1);
					# get_menu_choice()
		except (TypeError, ValueError):
			time.sleep(4)
			# get_menu_choice()

# Assuming that the 'region' function is defined elsewhere in your code.
# Make sure to define or import the 'region' function before calling 'scan_running_processes'.

# Example 'region' function:
def region(ip):
	# Implementation of 'region' function to find the country.
	# Replace this with the actual implementation.
	return "Unknown"

# Menu 4: Automated Local Port Scanner - Tested Pass
def automated_port_scanner():
	ports = []

	def check_internet(host="8.8.8.8", port=53, timeout=3):
		try:
			socket.setdefaulttimeout(timeout)
			socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
			return True
		except socket.error as ex:
			print(ex)
			return False

	def get_global_ip():
		ip = requests.get('https://checkip.amazonaws.com').text.strip()
		return ip

	def get_local_ip():
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		try:
			s.connect(('8.8.8.8', 1))
			ip = s.getsockname()[0]
		except:
			ip = '127.0.0.1'
		finally:
			s.close()
		return ip

	def port_scan(ip):
		remote_server = ip

		print(">" * 60)
		print("Scanning remote host", remote_server)
		print("<" * 60)

		try:
			for port in range(1, 65535):
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				result = sock.connect_ex((remote_server, port))
				if result == 0:
					print("Port {}: Open".format(port))
					ports.append(port)
				else:
					print("Port {}: Closed".format(port))
				sock.close()
		except socket.error:
			print("Can't connect to server")

	def main():
		print("=" * 24)
		print("P O R T	 S C A N N E R")
		print("=" * 24)

		t1 = datetime.datetime.now()

		online = check_internet()
		if online:
			print("Host is connected to the internet...")
		else:
			print("Host is offline...")
		print("=" * 24)

		g_ip = get_global_ip()
		l_ip = get_local_ip()
		print("Global ip: ", g_ip)
		print("Local ip: ", l_ip)
		print("=" * 24)

		port_scan(g_ip)
		port_scan(l_ip)

		t2 = datetime.datetime.now()
		elapsed_time = t2 - t1
		print("=" * 24)
		print("Time taken to complete scan: ", elapsed_time)

	main()

# Menu 5: Multi-threaded Port Scanner - Tested pass
def multi_threaded_port_scanner():
	# Start Threader3000 with clear terminal
	subprocess.call('cls', shell=True)

	# Main Function
	def qq():
		socket.setdefaulttimeout(0.30)
		print_lock = threading.Lock()

	# Welcome Banner
		print("-" * 60)
		print("		   Multi-threaded Port Scanner			")
		print("-" * 60)
		time.sleep(1)
		target = input("Enter your target IP address or URL here: ")
		error = ("Invalid Input")
		try:
			t_ip = socket.gethostbyname(target)
		except Exception:
			print("\n[-]Invalid format. Please use a correct IP or web address[-]\n")
			qq()
		#Banner
		print("-" * 60)
		print("Scanning target "+ t_ip)
		print("Time started: "+ str(datetime.datetime.now()))
		print("-" * 60)
		t1 = datetime.datetime.now()

		def portscan(port):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				conx = s.connect((t_ip, port))
				with print_lock:
					print("Port {} is open".format(port))
				conx.close()
			except:
				pass
				

		def threader():
			while True:
				worker = q.get()
				portscan(worker)
				q.task_done()
		q = Queue()
		
		startTime = time.time()
		
		for x in range(200):
			t = threading.Thread(target = threader)
			t.daemon = True
			t.start()

		for worker in range(1, 65535):
			q.put(worker)

		q.join()

		t2 = datetime.datetime.now()
		total = t2 - t1
		print("Port scan completed in "+str(total))
		print("-" * 60)
		get_menu_choice()

	if __name__ == '__main__':
		qq()

# Menu chooser
def get_menu_choice():
	def print_menu():
		# Set text color to bright red (works only in the final produced .exe in cmd)
		os.system('color 0c')
		print(30 * "-", "OC66 Network Tool", 30 * "-")
		print("1. IP/Domain Geolocation ")
		print("2. IP TRAFFIC LOGGER ")
		print("3. Scan Running Process ")
		print("4. Automated Local Port Scanner ")
		print("5. Multi-threaded Port Scanner ")
		print("6. Exit ")
		print(73 * "-")

	loop = True
	int_choice = -1

	while loop:
		print_menu()
		choice = input("Enter your choice [1-6]: ")

		if choice == '1':
			geolocate_ip()
			int_choice = 1
			loop = False
		elif choice == '2':
			ip_traffic_logger()
			int_choice = 2
			loop = False
		elif choice == '3':
			scan_running_processes()
			int_choice = 3
			loop = False
		elif choice == '4':
			automated_port_scanner()
			int_choice = 4
			loop = False
		elif choice == '5':
			multi_threaded_port_scanner()
			int_choice = 5
			loop = False
		elif choice == '6':
			print("Exiting..")
			loop = False
			sys.exit()
		else:
			generate_overcrash_art()
			print("Wrong menu selection. Try again.")

	return [int_choice, choice]

print(get_menu_choice())
