#freeleasehound.py
#2019 | dclark NCAR EOL/CWIG
#https://github.com/dclarkco/freeloaderHound
#monitors dhcp log for lingering devices on the network without a lease, and alerts sysadmins

#done:
#data intake, data parsing, regex, subnet 

#inprogress:
#data logging and checking, csv tmp storage, timeDelta

#todo:
#email, scheduling, tmp directory config, testing

#bugs:
#sniffLease needs to only report a diff tdelt if it is greater than the previous. The log should be read chronologically, I suspect it is updating the original time when i dont need to


from datetime import datetime 
import os, re, sys

#print(sys.version)
timeLimit = 3600 #seconds
debug = False
offenders = {}

def timeDeltaCalc(time1, time2):
	timeFormat = "%b %d %H:%M:%S"


	time1 = datetime.strptime(time1, timeFormat)
	time2 = datetime.strptime(time2, timeFormat)
	try:
		tDelta = (time2 - time1)
		return tDelta
	except:
		print("Time delta could not be calculated, time format must be wrong or missing")

def sniffLease():
	# loads, scans, and unloads log
	# returns dictionary of offenders 

	# Regex expressions:
	regexMAC = re.compile(ur'([0-9a-f]{2}(?::[0-9a-f]{2}){5})')
	regexFREE = "no free leases"
	regexTIME = re.compile('(\w{3} \d{2} \d{2}:\d{2}:\d{2})')
	regexNET = re.compile('[/][0-9]{2}')
	timeFormat = "%b %d %H:%M:%S"
	output_filename = os.path.normpath("tmp/dhcpfreeloaders.txt")

	#file IO:
	with open('dhcpd.log', 'r') as inFile:
		log = inFile.readlines()
		for line in log:
			if regexFREE in line:

				MAC = regexMAC.findall(line)[0] # search for all mac addresses in line and set to MAC
				NET = regexNET.findall(line)[0].strip('/')
				TIME = regexTIME.findall(line)[0]

				if MAC in offenders:
					metadata = offenders[MAC]
					tDelta = timeDeltaCalc(metadata[0], TIME) #check time delta of previous record against current
					#
					offenders[MAC].append(tDelta)
					print(MAC + " is lingering on a free lease for " + str(tDelta))

				# #strip time and set to 'time'
				 #use tdelta calc and time parsing to get time delta as timeDelta 
				offenders[MAC] = [TIME, NET] #first collection of offenders, change to only save if tdelta is >3600
				if(debug):
					print(line.strip('\n'))
				#save offenders as csv, ensure that it doesn't grow beyond scope of the data being handled
		if(debug):
			print(offenders)
		writeOffenders(offenders)			
		return offenders

def writeOffenders(offenders):
	import csv
	with open('offenders.csv', 'w') as csv_file:
		writer = csv.writer(csv_file)
		for key, value in offenders.items():
	   		writer.writerow([key, value])
	print("wrote "+ str(len(offenders)) + " offenders to disk...")

def readOffenders():
	with open('dict.csv') as csv_file:
		reader = csv.reader(csv_file)
		dictreader = dict(reader)

def sendSniffs(snifflist):
	#sends an email of the offenders saved to csv by sniffLease
	#using smtplib

	import smtplib

sniffLease()

