#freeleasehound.py
#2019 | dclark NCAR EOL/CWIG
"""
https://github.com/dclarkco/freeloaderHound
monitors dhcp log for lingering devices on the network without a lease, and alerts sysadmins

done:
data intake, data parsing, regex, timeDelta/parsing, email

inprogress:
tmp directory config, testing

todo:
dupe avoidance:
	only return results from within 9-12 hours of running, and only machines without a notification in the past 24
	only with warnings within an hour of running

bugs:
"""
import datetime, time
import os, re, sys


#print(sys.version)
timeLimit = 3600 #seconds
debug = True
offenders = {}

def sniffLease():
	# loads, scans, and unloads log
	# returns dictionary of offenders 

	# Regex expressions:
	regexMAC = re.compile(ur'([0-9a-f]{2}(?::[0-9a-f]{2}){5})')
	regexFREE = "no free leases"
	regexTIME = re.compile('(\w{3} \d{2} \d{2}:\d{2}:\d{2})|(\w{3}  \d{1} \d{2}:\d{2}:\d{2})')
	regexNET = re.compile('[/][0-9]{2}')
	timeFormat = "%b %d %H:%M:%S"
	#output_filename = os.path.normpath("tmp/dhcpfreeloaders.txt")

	#file IO:
	with open('dhcpd.log', 'r') as inFile:
		log = inFile.readlines()
		for line in log:
			if regexFREE in line:

				MAC = regexMAC.findall(line)[0] # search for all mac addresses in line and set to MAC
				NET = regexNET.findall(line)[0].strip('/')
				if(regexTIME.findall(line)[0][0] == ''):
					TIME = regexTIME.findall(line)[0][1]
				else:
					TIME = regexTIME.findall(line)[0][0]

				tDeltaMAX = 0
				tDelta = -1
				metadata = {}
				
				if MAC not in offenders:
					metadata["initTIME"], metadata["lingerTIME"], metadata["VLAN"]=TIME,tDeltaMAX,NET
					offenders[MAC] = metadata
				else:
					tDelta = timeDeltaCalc(offenders[MAC]["initTIME"],TIME)
					if((tDelta) > offenders[MAC]["lingerTIME"]):
						offenders[MAC]["lingerTIME"] = round(float(tDelta/3600),1)

				#save offenders as csv, ensure that it doesn't grow beyond scope of the data being handled
	if(debug):
		print(offenders, "log closed: "+str(inFile.closed))
	writeOffenders(offenders)
	return offenders


def timeDeltaCalc(time1, time2):
	timeFormat = "%b %d %H:%M:%S"

	time1 = datetime.datetime.strptime(time1, timeFormat)
	time2 = datetime.datetime.strptime(time2, timeFormat)
	try:
		tDelta = (time2 - time1)
		return tDelta.total_seconds()
	except:
		print("Time delta could not be calculated, time format must be wrong or missing")

def writeOffenders(offenders):
	import csv
	with open('/tmp/offenders.csv', 'w') as csv_file:
		writer = csv.writer(csv_file)
		writer.writerow(("MAC address", "VLAN", "network init time", "linger time (hrs)"))
		i = 0
		for key, value in offenders.items():
			if(value["lingerTIME"]>1):
				i+=1
				writer.writerow((key, value["VLAN"], value["initTIME"], value["lingerTIME"]))
	print("wrote "+ str(i) + " offenders to disk...")

def readOffenders():
	with open('offenders.csv') as csv_file:
		reader = csv.reader(csv_file)
		dictreader = dict(reader)

def sendSniffs():
	#sends an email of the offenders saved to csv by sniffLease
	import smtplib

	from email.mime.text import MIMEText

	with open('offenders.csv') as input:
		# Create a text/plain message
		msg = input.read()
		msg = msg.replace(',','  |  ')

	gmail_user = "flickybot@gmail.com"
	gmail_password = "G.clad58904"

	sent_from = "flickybot@gmail.com"
	to = "dclark@ucar.edu"
	subject = ("Network free lease sniffer: "+str(datetime.datetime.now().strftime('%m/%d/%y %H:%M')))
	body = msg

	email_text = """\
From: %s
To: %s
Subject: %s

Offenders found on local network listed below:

%s
	""" % (sent_from, to, subject, body)
	if(debug):
		print(email_text)
	try:
		server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
		server.ehlo()
		server.login(gmail_user, gmail_password)
		server.sendmail(sent_from, to, email_text)
		server.close()

		print 'Email sent!'
	except:
		print 'Something went wrong...'

sniffLease()

sendSniffs()

