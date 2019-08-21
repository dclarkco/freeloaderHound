#leasegatekeeper.py
#2019 | dclark NCAR EOL/CWIG

#monitors dhcp log for lingering devices on the network without a lease

from datetime import datetime
import os, re, sys

print(sys.version)
timeLimit = 3600 #seconds
debug = False
offendees = {}

def sniffLease():
	# loads, scans, and unloads log
	# returns dictionary of offendees 

	# Regex used to match relevant loglines
	regexMAC = re.compile(ur'([0-9a-f]{2}(?::[0-9a-f]{2}){5})')
	regexFREE = "no free leases"
	regexTIME = re.compile('(\w{3} \d{2} \d{2}:\d{2}:\d{2})')
	timeFormat = "%b %d %H:%M:%S"
	# Output file, where the matched loglines will be copied to
	output_filename = os.path.normpath("tmp/dhcpfreeloaders.log")
	# Overwrites the file, ensure we're starting out with a blank file


	# Open input file in 'read' mode
	with open('dhcpd.log', 'r') as inFile:
		log = inFile.readlines()
		# Loop over each log line
		for line in log:
			if regexFREE in line:
				if(debug):
					print(line)
			# If log line matches our regex, print to console, and output file
				MAC = regexMAC.findall(line)[0]
				time = (datetime.strptime(regexTIME.findall(line)[0], timeFormat))
				offendees [MAC] = [time, timeDelta
		print offendees


#def sendSniffs(snifflist)

sniffLease()
