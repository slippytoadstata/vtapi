#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import os

class colors:
	bold = '\033[1m'
	reset = '\033[0m'
	Bblack = '\033[40m'
	yellow = '\033[33m'
	red = '\033[1;31m'
	green = '\033[1;32m'

class VTAPI():
	def __init__(self):
		# Public APIKEY Goes Here
		self.apikey = ''
		self.base = 'https://www.virustotal.com/vtapi/v2/'

	def report(self, resource):
		url = self.base + 'file/report'
		params = {'apikey': self.apikey, 'resource': resource }
		response = requests.get(url, params=params)
		data = response.json()
		return data

	def scan_file(self, file):
		url = self.base + 'file/scan'
		params = {'apikey': self.apikey}
		files = {'file': (file, open(file, 'rb'))}
		response = requests.post(url, files=files, params=params)
		data = response.json()
		return data

def format(data, file):
	graph = get_graph(data['positives'], data['total'])
	print """ ######################################
\033[1m SHA256: \033[0m {}
\033[1m File: \033[0m {}
\033[1m Detection ratio: \033[0m {}/{} {}
\033[1m Analysis date: \033[0m {}
 ######################################
 """.format(data['sha256'], file, data['positives'], data['total'], graph, data['scan_date'])
 	scans = data['scans']
 	print " {}{}{:^20} | {:^7}| {:^8}{}".format(colors.Bblack, colors.yellow, 'Antivirus', 'result', 'Update', colors.reset)
 	for value in scans.items():
 		if value[1]['detected'] == False:
 			detected = '⚫'
 			print " {:20} | {}{:^7}{} | {:^8}".format(value[0],\
 			colors.green, detected, colors.reset, value[1]['update'])
 		else:
 			detected = '⚫'
 			print " {:20} | {}{:^7}{} | {:^8} -> {}".format(value[0],\
 			colors.red, detected, colors.reset, value[1]['update'], value[1]['result'])

def export(data, file):
	name = file +"-"+ data['scan_date']
	name = name.replace(' ', '-')
	log = """ --------------------------------------
 SHA256: {}
 md5: {}
 File: {}
 Detection ratio: {}/{}
 Analysis date: {}
 Permalink: {}
 --------------------------------------
 \n""" .format(data['sha256'], data['md5'], file, data['positives'], data['total'], data['scan_date'], data['permalink'])
	f = open('log/' + name, 'w')
	f.write(log)
	f.close()

def get_graph(positives, total):
	pos = ''
	neg = ''
	for i in range(0, positives):
		pos += '█'
	for x in range(0, total-positives):
		neg += '█'
	result = colors.red + pos + colors.green + neg + colors.reset
	return result

def banner():
	os.system('clear')
	__version__ = '0.1'
	banner = """        _              _ 
 __   _| |_ __ _ _ __ (_)
 \ \ / / __/ _` | '_ \| |
  \ V /| || (_| | |_) | |
   \_/  \__\__,_| .__/|_|
     %sVirusTotal%s |_| %sv%s%s\n"""
	print banner %(colors.yellow, colors.reset, colors.yellow, __version__, colors.reset)

def help():
	help = """
 VTAPI: Help
 usage: python vtapi.py [-f][file]

    -f  Shows report obtained by the scan
"""
	print help