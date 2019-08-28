#freeleasehound.py
#2019 | dclark NCAR EOL/CWIG

#monitors dhcp log for lingering devices on the network without a lease

#progress: 3/7

#done:
#data intake, data parsing, regex,  
#inprogress:
#data logging and checking,
#todo:
#email, scheduling


from datetime import datetime #don't ask me why this syntax enabled strptime and tdelta, I don't have an answer
import os, re, sys

print(sys.version)
timeLimit = 3600 #seconds
debug = False
offenders = {}

def timeDeltaCalc(time1, time2):
	try:
		tDelta = time2 - time1
		return tDelta
	except:
		print("Time delta could not be calculated, time format must be wrong or missing")

def sniffLease():
	# loads, scans, and unloads log
	# returns dictionary of offendees 

	# Regex expressions:
	regexMAC = re.compile(ur'([0-9a-f]{2}(?::[0-9a-f]{2}){5})')
	regexFREE = "no free leases"
	regexTIME = re.compile('(\w{3} \d{2} \d{2}:\d{2}:\d{2})')
	timeFormat = "%b %d %H:%M:%S"
	output_filename = os.path.normpath("tmp/dhcpfreeloaders.txt")

	#file IO:
	with open('dhcpd.log', 'r') as inFile:
		log = inFile.readlines()
		for line in log:
			if regexFREE in line:
				if(debug):
					print(line)
				MAC = regexMAC.findall(line)[0] # search for all mac addresses in line and set to MAC
				time = (datetime.strptime(regexTIME.findall(line)[0], timeFormat)) #strip time and set to 'time'
				timeDelta = timeDeltaCalc(time, time) #use tdelta calc to get time delta as timeDelta (if datetime function works, this will be removed)
				offenders [MAC] = [time, timeDelta] #final collection of offenders, might change it to only save if tdelta is >3600
		print offenders


#def sendSniffs(snifflist)


sniffLease()
