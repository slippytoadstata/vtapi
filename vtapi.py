#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Simple Virus Total API
Version: 0.1
Autor: qwartz -> twitter: @qwartz_
Github: https://github.com/qwartz/vtapi/
"""

import sys, os
from API.virustotal import *
vt = VTAPI()

menu = {
	'-f':'file',
	'-h':'help',
	'-v':'banner'
}

def main():
	banner()	
	argv = sys.argv
	if len(argv) > 1:
		if argv[1] in menu: load(argv)
	else:
		help()

def load(argv):
	option = menu[argv[1]]
	if len(argv) > 2:
		globals()[option](argv)
	else:
		globals()[option]()

def file(argv=False):
	if argv == False:
		print " E: File path required\n example: python vtapi.py -f ./test.exe\n"
	else:
		file = argv[2]
		if os.path.exists(file):
			print " [" + colors.green + "+" + colors.reset + "] Scan"
			result = vt.scan_file(file)
			sha256 = result['sha256']
			print " [" + colors.green + "+" + colors.reset + "] Report"
			result = vt.report(sha256)
			export(result, file)
			format(result, file)

if __name__ == '__main__':
	main()