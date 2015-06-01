# webchecker
# Angel Suarez-B (n0w)
# 06/2015
# Reads a list of URLs from an sqlite3 db, computes their sha1 and md5 hash and 
# compares them against previous results to determine if the URL content has changed. 
#!/usr/bin/env python2

import logging
import argparse
import urllib
import requests
import hashlib
import sqlite3
from time import gmtime, strftime 	

class Webchecker():
	def __init__(self, dbFile, args):
		self.mode = args.mode
		self.dbfile = dbFile
		self.timeout = 15
		self.headers = {}
		self.proxies = None
		self.mismatch = False
		
		# Initialize logger
		# Disable requests event logging
		logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(logging.WARNING)
		
		self.logger = logging.getLogger("webchecker")
		logging.basicConfig(filename="webchecker.log", level=logging.DEBUG, 
		format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s')
		
		# Initialize DB connection
		dbConnection = sqlite3.connect(dbFile)
		self.	dbCursor = dbConnection.cursor()
		sqlQuery = "SELECT * FROM elements"
		self.dbCursor.execute(sqlQuery)
		
		# Check 
		for element in self.dbCursor.fetchall():
			response = self.query(str(element[1]))
			# Check for valid resource	
			if response.status_code == 200:
				# Debug log level
				self.logger.debug("MD5({}) = {}".format(str(element[1]), hashlib.md5(response.text.encode('utf-8')).hexdigest()))
				self.logger.debug("SHA1({}) = {}".format(str(element[1]), hashlib.sha1(response.text.encode('utf-8')).hexdigest()))
				
				md5hash = hashlib.md5(response.text.encode('utf-8')).hexdigest()
				sha1hash = hashlib.sha1(response.text.encode('utf-8')).hexdigest()
				
				if self.mode == 'store':
					self.store(element[1], md5hash, sha1hash)
				else: # Compare
					if md5hash != element[2]:
						self.logger.info ("[!] Warning. MD5({}) hash ({}) differs from stored hash {} on {}".format(element[1], md5hash, element[2], element[0]))
						self.mismatch = True
					else:
						self.logger.debug("[*] MD5({}) hash ({}) matches stored hash on {}".format(element[1], element[2], element[0]))
					
					if sha1hash != element[3]:
						self.logger.info("[!] Warning. SHA1({}) hash ({}) differs from stored hash {} on {}".format(element[1], sha1hash, element[3], element[0]))
						self.mismatch = True
					else:
						self.logger.debug("[*] SHA1({}) hash ({}) matches stored hash on {}".format(element[1], element[3], element[0]))
			else:
				print "[e] Resource {}: {}".format(str(element[1]),response.reason)
		
		dbConnection.commit()
		dbConnection.close()
		
		okString = "[*] Everything is OK :)"
		badString = "[e] Warning! Mismatches found!! :/"
		
		if self.mismatch == False:	
			self.logger.info(okString)
			print okString
		else:
			self.logger.info(badString)
			print badString
			
		
	def store(self, key, md5, sha1):
		sqlQuery = "UPDATE elements SET date = ?, md5sum = ?, sha1sum = ? WHERE URL=?"
		print sqlQuery
		timestamp = strftime("%H:%M:%S %d/%m/%Y", gmtime())
		self.dbCursor.execute(sqlQuery, (timestamp, md5, sha1, key))
			
	def query(self, URL):
		resp = None
		try:
			if self.proxies:
				resp = requests.get(URL, proxies=self.proxies, verify=False, headers=self.headers, timeout=self.timeout)
			else:
				resp = requests.get(URL, verify=False, headers=self.headers, timeout=self.timeout)
			
		except Exception, e:
			print "Error getting data from host: {0}".format(e)

		return resp

if __name__ == '__main__':
	print "      -- webchecker --"
	print "Angel Suarez-B (n0w) 06/2015\n"
	
	parser = argparse.ArgumentParser(description="Takes or compares 'hash snapshots' from URLs stored in a sqlite3 db.")
	parser.add_argument("mode", choices=['compare','store'], help="""Establishes work mode. 'Compare mode' calculates
																md5 and sha1 and compares them against previously stored values. 
																'Store mode' stores calculated values.""")
	args = parser.parse_args()
	myChecker= Webchecker("elements.db", args)
	
	
