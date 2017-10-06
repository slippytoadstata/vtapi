#!/usr/bin/env python
# -*- coding: utf-8 -*-}

import requests
import os

class colors:
    bold   = '\033[1m'
    reset  = '\033[0m'
    Bblack = '\033[40m'
    yellow = '\033[33m'
    red    = '\033[1;31m'
    green  = '\033[1;32m'

class VTAPI():
    def __init__(self):
        # Public APIKEY Goes Here
        self.apikey = ''
        self.base = 'https://www.virustotal.com/vtapi/v2/'

    def report_file(self, resource):
        url = self.base + 'file/report'
        params = {'apikey': self.apikey, 'resource': resource }
        response = requests.get(url, params=params)
        return response.json()

    def report_url(self, resource):
        url = self.base + 'url/report'
        params = {'apikey':self.apikey, 'resource':resource}
        response = requests.get(url, params=params)
        return response.json()
        
    def scan_file(self, file):
        url = self.base + 'file/scan'
        params = {'apikey': self.apikey}
        files = {'file': (file, open(file, 'rb'))}
        response = requests.post(url, files=files, params=params)
        return response.json()

    def scan_url(self, resource):
        url = self.base + 'url/scan'
        params = {'apikey':self.apikey, 'url':resource}
        response = requests.post(url, data=params)
        return response.json()

def format(data):
    info = data['permalink']
    info = info.split('/')
    graph = get_graph(data['positives'], data['total'])
    abstract(data, graph, info)
    scans = data['scans']
    table(scans, info)

def table(scans, info):
    if "file" in info:
        print " {}{}{:^20} | {:^7}| {:^8} | {:^10}{}"\
        .format(colors.Bblack, colors.yellow, 'Antivirus', 'Result', 'Update', 'Detail', colors.reset)
        for value in scans.items():
            if value[1]['detected'] == False:
                detected = '⚫'
                print " {:20} | {}{:^7}{} | {:^8} |".format(value[0],\
                colors.green, detected, colors.reset, value[1]['update'])
            else:
                detected = '⚫'
                print " {:20} | {}{:^7}{} | {:^8} | {:^10}".format(value[0],\
                colors.red, detected, colors.reset, value[1]['update'], value[1]['result'])
    
    elif "url" in info:
        print " {}{}{:^25} | {:^7}| {:^8}{}"\
        .format(colors.Bblack, colors.yellow, 'Antivirus', 'Result', 'Detail', colors.reset)
        for value in scans.items():
            if value[1]['detected'] == False:
                detected = '⚫'
                print " {:25} | {}{:^7}{} |".format(value[0],\
                colors.green, detected, colors.reset)
            else:
                detected = '⚫'
                print " {:25} | {}{:^7}{} | {:^10}".format(value[0],\
                colors.red, detected, colors.reset, value[1]['result'])
    
def abstract(data, graph, info):
    print "\n + ------------------------------- +"
    if "file" in info:
        print " sha1:", data['sha1'], "\n sha256:", data['sha256'], "\n md5:", data['md5'],
    
    elif "url" in info:
        print " Url:", data['url'],
    
    print """\n Detection ratio: {}/{} {}
 Analysis date: {}
 Permalink: {}
 + ------------------------------- +
 """.format(data['positives'], data['total'], graph, data['scan_date'], data['permalink'])
        
def export(data):
    name = data['scan_date']
    log = """ --------------------------------------
 Detection ratio: {}/{}
 Analysis date: {}
 Permalink: {}
 --------------------------------------
 \n""" .format(data['positives'], data['total'], data['scan_date'], data['permalink'])
    f = open('log/' + name, 'w')
    f.write(log)
    f.close()

def get_graph(positives, total):
    positive = ''
    negative = ''
    for i in range(0, positives): positive += '█'
    for x in range(0, total-positives): negative += '█'
    result = colors.red + positive + colors.green + negative + colors.reset
    return result

def banner():
    os.system('clear')
    __version__ = '1.1'
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
 usage: python vtapi.py [-f][-u][file | url]

    -h  Show help
    -f  Scan file and show results
    -u  Scan a url and show results
"""
    print help

