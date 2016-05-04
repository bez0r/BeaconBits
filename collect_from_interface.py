#!/usr/bin/env python

import scapy
from scapy.all import *
import sys,os
import redis
import datetime

RED_IS = redis.StrictRedis(host='127.0.0.1', port=6379, db=1)

if len(sys.argv) != 2:
    print "[*] Usage: collect_from_interface.py <foo.pcap>"
    exit(0)
filename=sys.argv[1]
a=rdpcap(filename)

from scapy.all import sr1,IP,UDP,TCP

for pkt in a:
    timer = str(pkt.time)
    Fixtime = int(timer[0:10])
    working_date = time.strftime('%Y%m%d', time.gmtime(pkt.time))
    try:
        #print pkt[IP].src,pkt[IP].dst
        quantset = str(pkt[IP].src)+":"+str(pkt[IP].dst)+":"+str(pkt[TCP].dport)+":"+working_date
        keyset_ipsrc = "ip_src:" + str(pkt[IP].src) +':'+ str(working_date) 
        keyset_ipdst = "ip_dst:" + str(pkt[IP].dst) +':'+ str(working_date)
        RED_IS.sadd('SET:'+quantset, Fixtime)
        RED_IS.incr(keyset_ipsrc)
        RED_IS.incr(keyset_ipdst)
    except:
        if args.debug: print "Initial polling, error if this message repeats",line
print 'capture completed, running analysis'
  

