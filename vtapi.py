#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Virus Total API
version : 0.1
 author : qwartz -> twitter: @qwartz_
 github : https://github.com/qwartz/vtapi/
"""

import sys, os
from API import *
vt = VTAPI()

menu = {
    '-f':'file',
    '-h':'help',
    '-v':'banner'
}

def main():
    banner()
    if vt.apikey != '':
        argv = sys.argv
        if len(argv) > 1:
            if argv[1] in menu: load(argv)
        else:
            help()
    else:
        print " W: Check file: API/virustotal.py (line: 17)"
        vt.apikey = raw_input(' An apikey is required: ')
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
        else:
            print " E: file", colors.bold + file + colors.reset, "does not exist"

if __name__ == '__main__':
    main()
