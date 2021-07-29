import os, re, sys, socket, json, traceback, ntpath
import time
import urllib3
from lxml import etree
import datetime
import subprocess
import threading
import signal
import requests
from queue import Queue
import signal
os.system('color 0c')  #set text color to bright red [only works in final produced .exe (cmd type prompt)]
def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    get_menu_choice()
signal.signal(signal.SIGINT, signal_handler)
#Menu 1:
def start():
	bb=raw_input("Please enter IP or Domain Address to Geo locat: ")
	commandLineArraySize = len(sys.argv)
	querySearch = str(bb)
	queryUrl = re.match("^(http[s]?://)?([a-z0-9.]{1,})[/]?([a-z]{1,})?(/.*)?$", querySearch)
	if queryUrl:
		querAddress = queryUrl.group(2)
		try:
			queryIp = socket.gethostbyname(querAddress)
		except:
			print "Invalid Address"
			time.sleep(4)
			start()
	try:
		queryIp
	except:
		if re.match("^(([1]?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}([1]?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))$", querySearch):
			queryIp = querySearch
		else:
			print "Invalid IP Address"
			time.sleep(4)
			start()
	else:
		ipInforArray = []
		if len(ipInforArray) == 0:
			ipInforArray = ipInfoFetch(queryIp)
		if len(ipInforArray) == 0:
			print "Unable to Check IP Address, try again later"
			start()
		print"IP: %s\nHosted by: %s\nCity: %s\nCountry: %s" % (ipInforArray[0], ipInforArray[1], ipInforArray[2], ipInforArray[3])
		time.sleep(4)
		get_menu_choice()

# Search funcion using geoipfetch.net and/or ip-api.com
def ipInfoFetch(queryIp):
	ipDataArray = []
	utf8_parser = etree.XMLParser(encoding='utf-8')
	geoIpLookupUrl = 'http://api.geoiplookup.net/?query=' + queryIp
	ipApiUrl = 'http://ip-api.com/json/' + queryIp
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

#Menu 2:
def ipscan():
	print '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$' # Introduction%%%%%%%%%%%%%%%%%%%%%%%%%
	print '$$$$$$$$$$$$$$$$$$$$$  IP TRAFFIC LOGGER $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
	print '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'

	#nothin=raw_input('<Press enter to start scanning>') #wait for user input
	running=1 #parameter which controls below while loop 
	scannum=1 #parameter which counts how many scan logs have been printed
	first_run = 1
	Unique_LIST=[] #list of unqiue strings <outgoing_ip>_<PID>_<process_name> from processes

	# Functions @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

	def timeouttest(api1T,api2T,timeout_input,echo_text): # timeout and connection test to see if API are available
		api1T=0
		api2T=0
		if echo_text==1:
			print '\t Performing connection test for API .....'
			print '\t   [geo-location of ip-address]'
		try: #test timeout on main ip-detail grab api [best]
			r = requests.get('http://ip-api.com/', timeout=timeout_input) # limited to 1000 IP lookups in a day for free account
		except requests.Timeout:
			api1T=1
		except: 
			api1T=1
		try: #test timeout on secondary ip-detail grab api
			r = requests.get('https://ipapi.co/', timeout=timeout_input) # limited to 1000 IP lookups in a day for free account
		except requests.Timeout:
			api2T=1
		except: 
			api2T=1
		if echo_text==1:
			print '\t ...Test complete!\n'
		return api1T, api2T
	#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	#Exclud_process=[]
	api1_timeout=0
	api2_timeout=0
	#txtfile_err=0;
	# MAIN SECTION OF CODE [CONTINOUS SCANNING until program close or error] ####################################################################################
	while running == 1: #Continous scanning of outgoing/ingoing ip related to running processes [whilst running=1]
		try: #Try running main section of code $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
			api_connect_attempt=0
			api_timeout_persist=0
			#Exclud_process,txtfile_err=process_exclude_obtain(Exclud_process,txtfile_err,1)
			if first_run == 1 :
				api1_timeout,api2_timeout=timeouttest(api1_timeout,api2_timeout,2,1) # timeoutctest
				if api1_timeout == 1 and api2_timeout == 1:  # if both connections timed out
					print '\n None of the two Api ARE available to obtain locational data for ip-addresses [all had time-out connection]'
					print 'Connection will be retested before next scan.......\n'
				first_run = 0 
			profilesNEW=[] #initialize (empty) list of profiles (tasks and details) picked up in scan
			tasks=[] #initialize (empty) list of tasknames picked up in scan
			now=datetime.datetime.now() #current date and time
			k=subprocess.Popen(['netstat','-ano'],stdout=subprocess.PIPE) #record (and connect) data of running cmd command 'netstat -ano'
			#"netstat -ano" cmd command is a list of detected running processes and their respective;
			# outgoing/ingoing ip address, PID and Image name        
			profilesNEW=re.findall('(.*)ESTABLISHED(.+)\r',k.communicate()[0]) #gets list of processes for which ip connection has been established
			tasks = os.popen("tasklist").readlines()  #get list of processes detected as currently running (cmd)
			del tasks[0] #removes(deletes) first row from "tasks" (which is just a blank line)
			del tasks[0] #removes(deletes) next row from "tasks" (which is just column headers of output from tasklist command)
			del tasks[0] #removes(deletes) next row from "tasks" (which is seperator of column header from data in columns)
			# final "tasks" is just tasklist data; image name
			#[below] cur=parameter which keeps track of current process being seperated into distinct data (start cur=0)
			for cur,x in enumerate(tasks,start=0): #enumerate through each element of "tasks"
				tasks[cur]=tasks[cur].split() #split each element (sentence) of "tasks" into distinc element
			r=[] #initialise list of established connections which will be complete collection of imname,PID, out/in IP etc... (for each process)
			y=[] #initialise list which will be collection of ip address and PID which has made "established connection
			for x in profilesNEW : #iterate through each element of "profilesNEW" (which are list of tasks with establish connection to external ip)
				#each x has form  ('  TCP    192.168.0.18:54914     54.230.245.51:443      ', '     5548')
				# which is        (' {con. type} {ingoing ip}:{port} {outgoing ip}:{port}   ', '    PID ')          
				y=x[0]+x[1] #y is =(' {con. type} {ingoing ip}:{port} {outgoing ip}:{port}  PID')   [x combined]
				y=y.split() #get elements of y which are disinct by seperation of ' ' that is y=[{con. type},{ingoing ip}:{port},{outgoing ip}:{port},PID]
				y[1]=y[1].split(':')[0] #y[1]={ingoing ip}  (remove ":{port}")
				y[2]=y[2].split(':')[0] #y[2]={outgoing ip}   (remove ":{port}")  
				#y is now =[{con. type},{ingoing ip},{outgoing ip},PID]            
				pf=0 #parameter which indicates if at least one PID of "tasks"
				for z in tasks: #for each row,z= imagename,PID,etc... for "tasks"
					if z[1] in y[3] and '.exe' in z[0]: #if PID z[1] in PID of y and is image name is .exe (not something else due to error)
						y.append(z[0]) #apprend image name to to related y (by PID between tasks and y)
						pf=1 #set parameter to 1 which indicates at least one "Established" connection has been found
				if pf == 0: #if not at least one relation of PID between tasks and y
					y.append('Process Unkown/dead') #apped string that 'process is dead/unknown' (used later in code)
				r.append(y) #append final y to r (data in y was found to have relation to a running process listed in "tasks")
			newscan=0 #initialise parameter which, if =1, indicates at least one new establish ip connection and currently running process has been found
			nw=[] #list of these new processes 
			for x in r: #for each element of r (list of running process (PID,imname,ip) with an established connection)
				if x[2]+'_'+x[3]+'_'+x[4] not in Unique_LIST and x[2] != '127.0.0.1': #if this element of r has PID or image name (process name) unique to previously logged establish connecitons                
					nw.append(x) #append to list of unique establish process
					Unique_LIST.append(x[2]+'_'+x[3]+'_'+x[4]) #add <outgoing_ip>_<PID>_<process_name> to unique list
					newscan=1 #set newscan parameter to 1 to indicate a new printout of at least one unique established process will be printed
			if newscan == 1: #if new scan =1 [if newscan=0, no new log is to printed and "while loop" starts again with new scan]
				#Exclud_process,txtfile_err=process_exclude_obtain(Exclud_process,txtfile_err,1) # re-read text-file to see if new excludes added
				print 'Scan number '+str(scannum)+'##########################################' #indicate number scan log being printed
				print ' time performed: '+str(now)+'\n'   #indicate time that this scan was performed at (will be give or take ~10 seconds)
				api1_timeout,api2_timeout=timeouttest(api1_timeout,api2_timeout,2,0) # timeoutctest
				print ' Internal IP || Foreign IP (country,state;city - organisation) || PID || Process name' #header names of printed data
				for x in nw: #for each element of list of newly establish (connect) process to be logged
						if api1_timeout ==0: # if primary api did not time out
							try: #try to obtain country,state,city of outgoing (foriegn) ip address [if error, go to "catch"]               
								ip_details=urllib.urlopen('http://ip-api.com/csv/'+x[2]).read().split(',') #read html of ip details from website
								country=ip_details[1] #record country name related to foreign ip address
								state=ip_details[3] #record state name related to foreign ip address
								city=ip_details[5] #record city name related to foreign ip address
								org=ip_details[11] #record organisation name related to foreign ip address 
							except: #if error with recording details of interest in "try:"
								if x[2] in '127.0.0.1': #assess wether "foreign" ip is just local (internal) ip address
									country='local_host' #set "country name"
									state='[internal]' #set "sity name"
									city='' #leave city name blank
									org =''
								else: #else if country,state,city could not be obtain (for other circumstances)
									country='N/A' #set country name to 'N/A' ('Not available)
									state='' #leave state name blank
									city='' #leave city name blank
									org =''
						else: #if primary api timed out
							if api2_timeout ==0: # if secondary api did not time out
								country=''
								state=''
								city=''
								org =''
								if x[2] in '127.0.0.1': #assess wether "foreign" ip is just local (internal) ip address
									country='local_host' #set "country name"
									state='[internal]' #set "sity name"
									city='' #leave city name blank
									org =''
								else: #else if country,state,city could not be obtain (for other circumstances)
									try:
										ip_details=urllib.urlopen('https://ipapi.co/'+x[2]+'/csv/').read().split('\r\n')[1]  
										country=ip_details[5] #record country name related to foreign ip address
										state=ip_details[3] #record state name related to foreign ip address
										city=ip_details[1] #record city name related to foreign ip address
										org =ip_details[12] #record organisation name related to foreign ip address 
									except:
										country='N/A'
										state='N/A'
										city='N/A'     
										org='N/A'   
							else:
								country='N/A'
								state='N/A'
								city='N/A'
								org='N/A'
								if api_connect_attempt < 5: # if 5 or more consecutive timoute for all api / skip connect test on current scan to save time
									api1_timeout,api2_timeout=timeouttest(api1_timeout,api2_timeout,1,0) # timeoutctest
									if api1_timeout == 1 and api2_timeout == 1:
										api_connect_attempt += 1
									else:
										api_connect_attempt = 0   
								else:
									api_timeout_persist=1 #
						print x[1]+' || '+x[2]+'('+country+','+state+';'+city+'-'+org+') || '+x[3]+' || '+x[4]            
						#(above) print; Internal IP + Foreign IP (country,state;city) + PID + Process name
						
				print '######################################################################\n'
				if api_timeout_persist==1: # if api timeout persistent
					print '\n Both API, used to obtain locational data for ip-addresses, were found to'
					print 'have persist time-out issues on this scan (note: require internet connection)\n'
				print 'ACTIVELY SCANNING, NEW RESULTS WILL BE DISPLAYED.......'
				get_menu_choice()
				#scannum += 1 #update parameter which indicates a new scanlog has just been printed (count of logs printed)
				#running=0
				#Exclud_process,txtfile_err=process_exclude_obtain(Exclud_process,txtfile_err,1) # re-read text-file to see if new excludes added
		except Exception as er2:#If error was experience in main code section $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
		   running=0  #above (related error is recorded as 'er2') and while loop param (running) set 0 to break scanning
		   exit()

#Menu 3:
def region(ip):
	try:
		if ip != "127.0.0.1": #Check to see if localhost is showing
			r = requests.get("http://ip-api.com/json/"+str(ip)).json()
			if r["status"] == "success":
				return r["timezone"]
			else:
				return "fail";
		else:
			return "fail";
	except ConnectionError:
		time.sleep(5);
		zz()
		
def zz():
	while True:
		try:
			u=subprocess.Popen(["netstat","-n"], stdout=subprocess.PIPE, shell=True).stdout.read().splitlines(); #retrieve input
			for x in range(4,len(u)): #First 4 lines are rubbish
				p=len(u[x])-11; #Eliminates state and most whitespace
				ipaddr,port=str(u[x])[32:p].strip().split(":"); #First 33 are other crap, strip removes whitespace, split removes ":" + makes variables
				time.sleep(1);
				if ipaddr != "127.0.0.1":
					#print("Please wait i need to scaning your network")
					place=region(ipaddr); #Find country
					#k=requests.get("http://ip-api.com/json/"+a).json()["country"];
					print"IP: {0} \nplace: {1} \nPort: {2}\n========".format(ipaddr,place,port); # print
				else:
					print"N/A"
					#time.sleep(1);
					#get_menu_choice()
		except (TypeError, ValueError):
				time.sleep(4);
				get_menu_choice()
#Menu 4:
def Pscan():
	ports = []
	def checkinternet(host="8.8.8.8", port=53, timeout=3):
	  try:
		socket.setdefaulttimeout(timeout)
		socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
		return True
	  except socket.error as ex:
		print(ex)
		return False

	def get_globalip():
		ip = requests.get('https://checkip.amazonaws.com').text.strip()
		return ip

	def get_localip():
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		try:
			s.connect(('8.8.8.8', 1))
			ip = s.getsockname()[0]
		except:
			ip = '127.0.0.1'
		finally:
			s.close()
		return ip

	def portscan(ip):
		remoteServer = ip

		print (">" * 60)
		print ("Scanning remote host", remoteServer)
		print ("<" * 60)

		try:
			for port in range(1,65535):  
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				result = sock.connect_ex((remoteServer, port))
				if result == 0:
					print ("Port {}: 	 Open".format(port))
					ports.append(port)
				sock.close()
		except socket.error:
			print ("Can't connect to server")

	def main():
		#subprocess.call('clear', shell=True)
		print("="*24)
		print("P O R T   S C A N N E R")
		print("="*24)

		t1 = datetime.datetime.now()

		online = checkinternet()
		if(online==True):
			print"Host is connected to the internet..."
		else:
			print"Host is offline..."
		print("="*24)

		gIP = get_globalip()
		lIP = get_localip()
		print"Global ip: ", gIP
		print"Local ip: ", lIP
		print("="*24)

		portscan(gIP)
		portscan(lIP)

		t2 = datetime.datetime.now()
		time =  t2 - t1
		print("="*24)
		print"Time taken to complete scan: ", time
	main()
	
#Menu 5:
def s3000():
	# Start Threader3000 with clear terminal
	subprocess.call('clear', shell=True)

	# Main Function
	def qq():
		socket.setdefaulttimeout(0.30)
		print_lock = threading.Lock()

	# Welcome Banner
		print("-" * 60)
		print("        Threader 3000 - Multi-threaded Port Scanner          ")
		print("-" * 60)
		time.sleep(1)
		target = raw_input("Enter your target IP address or URL here: ")
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

#Menu chooser
def get_menu_choice():
	def print_menu():		# Your menu design here
		print(30 * "-", "OC66 Network Tool", 30 * "-")
		print"1. IP/Domain Geolocation "
		print"2. IP TRAFFIC LOGGER "
		print"3. Scan Runing Process " 
		print"4. Automated Local Port Scanner "
		print"5. Multi-threaded Port Scanner "
		print"6. Exit "
		print(73 * "-")

	loop = True
	int_choice = -1

	while loop:			 # While loop which will keep going until loop = False
		print_menu()	# Displays menu
		choice = input("Enter your choice [1-6]: ")

		if choice == 1:
			choice = ''
			while len(choice) == 0:
				start()
			int_choice = 1
			loop = False
		elif choice == 2:
			choice = ''
			while len(choice) == 0:
				ipscan()
			int_choice = 2
			loop = False
		elif choice == 3:
			choice = ''
			while len(choice) == 0:
				zz()
			int_choice = 3
			loop = False
		elif choice == 4:
			choice = ''
			while len(choice) == 0:
				Pscan()
			int_choice = 4
			loop = False
		elif choice == 5:
			choice = ''
			while len(choice) == 0:
				s3000()
			int_choice = 5
			loop = False
		elif choice == 6:
			int_choice = -1
			print"Exiting.."
			loop = False  # This will make the while loop to end
			exit()
		else:
			# Any inputs other than values 1-4 we print an error message
			raw_input("Wrong menu selection. try again..")
	return [int_choice, choice]

print(get_menu_choice())
