#!/usr/bin/env python3

import re
import sys
import pydig
import argparse

parser = argparse.ArgumentParser(description="SPF, DMARC and DKIM are queried for host")
parser.add_argument('host', help="This is the FQDN that will be queried")
parser.add_argument('-s', help="DKIM selector", nargs='+')
parser.add_argument('--savvy', help="it will query all DNS types in order", action='store_true')
parser.add_argument('--version', action='version', version='%(prog)s 1.0')
args = parser.parse_args()

qtype = 'txt'
common_selector_list = ['dkim', 'default', 'selector', 'selector1', 'selector2', 'google', 'zoho']
host = args.host

resolver = pydig.Resolver(nameservers=['8.8.8.8', '1.1.1.1'])

def spf():
    qspf = resolver.query(host, qtype)
    mspf=re.findall(r'"v=spf1.*?"', str(qspf), flags=re.M)
    if not mspf:
       print("No SPF record found for ", host) 
    else:
        for y in mspf:
                    print("SPF:", y)
        print()

def dmarc():
    qdmarc = '_dmarc.' + host
    mdmarc = resolver.query(qdmarc, qtype)
    if not mdmarc:
        print("No DMARC record found for", host)
    else:
        print("DMARC:", mdmarc[-1])
    print()

def dkim():
    if args.s:
        selector = args.s
    else:
        selector = common_selector_list

    for x in selector:
        qdkim = x + '._domainkey.' + host
        mdkim = resolver.query(qdkim, qtype)
        if (mdkim):
            print("DKIM: {}\n".format(x), mdkim[-1])
        else:
            if mdkim is None:
                print("Couldn't find a DKIM record associated with {} \nIf you know the correct selector add it using \"-s\" tag".format(host))

def savvy():
    for query_type in pydig.QueryType:
        print(query_type, resolver.query(host, query_type))

spf()
dmarc()
dkim()
if args.savvy:
    print()
    savvy()
