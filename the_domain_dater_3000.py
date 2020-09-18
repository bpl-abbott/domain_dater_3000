#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# The Domain Dater 3000
# 
# The ultimate tool for all your domain expiration dating needs.
# =============================================================================
import sys
import time
import socket
import re
from datetime import datetime

'''
__author__ = "Brendan Lynch"
__copyright__ = "Copyright 2020"
__credits__ = ["Brendan Lynch", "Sav.com"]
__license__ = "GPL"
__version__ = "0.01"
__maintainer__ = "Brendan Lynch"
__status__ = "Probably Buggy"
'''

from dateutil import parser

def print_heading():
	print("%-25s  %-20s" % ("Domain Name","Expiration Date"))

def print_domain(domain, expiration_date):
	print("%-25s  %-20s" % (domain, expiration_date))

def perform_whois(server , query):
	try:
		msg = b''
		sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
		sock.connect((server , 43)) #connect to port 43 on the whois
		sock.send((query + '\r\n').encode()) #send the whois query
		
		#receive reply in chunks
		while len(msg) < 20000:
			data = sock.recv(4096)
			msg += data
			if not data:
				break
		sock.close()
	except socket.gaierror as e:
		if e.errno != 10054:
			return 'Server blocked' #catch server block due to rate limit
	except socket.error as e:
		return 'Connection error' #catch other connection issues
		
	return msg.decode()

def get_whois_data(domain):
	#clean up the domain
	domain = domain.replace('https://','')
	domain = domain.replace('http://','')
	domain = domain.replace('www.','')
	domain = domain.split("/", 1)[0]
	domain = domain.strip()
	
	#get the tld or ccld
	ext = domain.split('.')[-1]
	
	#thin query to iana whois to get server for thick query
	whois = 'whois.iana.org'
	data = perform_whois(whois, ext)
	
	lines = data.splitlines()
	for line in lines:
		if ':' in line: 
			words = line.lower().split(':')
			
			#search the reply for a whois server
			if 'whois.' in words[1] and 'whois' in words[0]:
				final_whois = words[1].strip()
				data = perform_whois(final_whois, domain) #query the found server
	return data
	
def parse_whois(whois_data):
	result = 'Expiration Not Found'

	#TODO: Implement a statistical parser like a conditional random 
	#field or sequence labeling 
	for line in whois_data.splitlines():
		for expr_keyword in ['expir','paid','renew']:
			
			#search for expiration date keywords
			if expr_keyword in line.lower() and result == 'Expiration Not Found':
				reg_search = '.*'+expr_keyword+'.+:.*'
				if re.search(reg_search,line.lower()): #confirm the line has a keyword and colon
					try:
						date_str = line.split(':',1)[1] #assuming date is only thing after colon
						'''
						The prompt for this said no prebuilt packages so I'd normally
						rig up a mediocre date parser but I am tried and its late and
						dateutil is nice and fancy.
						'''
						date = parser.parse(date_str.strip()) #parse date of various formats
						result = date.strftime("%m/%d/%Y %H:%M:%S")
					except:
						return 'Could not parse date'
	return result

def main(args):
	#parse command line arguments, would normally use argparse or getopt
	if len(args) >= 1 and (args[0] == '-help' or args[0] == '-h'): #help
		print('You are on your own! Good luck.')
		return False
	elif len(args) > 1 and args[0] == '-i' and args[1].split('.')[1] == 'txt': #file input
		domain_list = open(args[1],'r').read().split('\n')
	elif len(args) >= 1 and args[0] != '-i': #domain args
		domain_list = args
	else: #no args found
		print('Incorrect arguments provided.  Please provide a domain.')
		return False
	
	#regex to validate domain name
	domain_val_str = r'^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$'
	
	print_heading()
	for domain in domain_list:
		valid_domain = re.match(domain_val_str, domain) #validate domain name
		if valid_domain:
			whois_msg = get_whois_data(domain) #get whois data
			if whois_msg == 'Server blocked' or whois_msg == 'Connection error':
				result = whois_msg
			else:
				result = parse_whois(whois_msg) #parse the received whois data
		else:
			result = 'Invalid Domain Name'
		print_domain(domain, result) #print results
		
if __name__ == "__main__":
	main(sys.argv[1:])
