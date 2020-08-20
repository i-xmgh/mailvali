#!/usr/bin/env python3


import re
import sys
import pydig

host=sys.argv[1] #input hostname
# qtype=sys.argv[2] #input DNS query type
# s=sys.argv[3] #input dkim selector
qtype='txt' 

def spf():
    spf1=pydig.query(host, qtype)
    RE=re.findall(r'(v=spf1)(.*?)"', str(spf1), flags=0)
    if RE==[]:
        print("\nNo SPF record found for", host)
    else:
        for y in RE:
            print("SPF:", y)
    print()

def dmarc():
    dm='_dmarc.' + host
    dmarc=pydig.query(dm, qtype)
    if dmarc ==[]:
        print("\nNo DMARC record found for", host)
    else:
        print("DMARC:", str(dmarc[-1]))
    print()

def dkim():
    for s in ['dkim', 'default', 'selector', 'selector1', 'selector2', 'google', 'zoho']:
        dk=s + '._domainkey.' + host
        dkim=pydig.query(dk, qtype)
        for x in dkim:
            if x !=None: #it seems this doesnt work
                print("DKIM:", str(dkim[-1]))
            else: #it seems this doesnt work
                print("Couldn't verify DKIM record") #it seems this doesnt work
    print()

class Report():
    print("DNS records for",host, "\nSPF, DMARC and DKIM are queried\n")
    spf()
    dmarc()
    dkim()