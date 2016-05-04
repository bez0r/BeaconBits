# beacon collect
# __author__ = "Kevin Noble"
# __credits__ = ["Pete Nelson"]
# 
# __license__ = "GPLv3"


import scapy
from scapy.all import *
import sys
import redis
import time

RED_IS = redis.StrictRedis(host='127.0.0.1', port=6379, db=1)

if len(sys.argv) != 2:
    print "[*] Usage: collect_from_file.py <foo.pcap>"
    exit(0)

filename=sys.argv[1]
a=rdpcap(filename)
from scapy.all import sr1,IP,UDP,TCP

for pkt in a:
    timer = str(pkt.time)
    Fixtime = int(timer[0:10])
    working_date = time.strftime('%Y%m%d', time.gmtime(pkt.time))
    port_set = 0
    if pkt.haslayer(TCP):
        port_set  = str(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        port_set = str(pkt[UDP].dport)
    else:
        port_set = 0
    quantset = str(pkt[IP].src)+":"+str(pkt[IP].dst)+":"+str(port_set)+":"+str(working_date)
    print quantset
    keyset_ipsrc = "ip_src:" + str(pkt[IP].src) +':'+ str(working_date) 
    keyset_ipdst = "ip_dst:" + str(pkt[IP].dst) +':'+ str(working_date)
    RED_IS.sadd('SET:'+quantset, Fixtime)
    RED_IS.incr(keyset_ipsrc)
    RED_IS.incr(keyset_ipdst)
print 'capture completed'

