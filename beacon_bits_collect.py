# !/usr/bin/env python

#
# This is the collector, it can be used with a coninuous collection from a flow feed or
# it can be use to read a file or file(s) saved in the argus flow format.
#
# code to parse flows from argus although, any flow tool that can output comma seperated fields can be used.
# Seek specifically TCP packets, the associated time in unix date format,
# source IP along with Destination IP and port.

# source feed does not have to be Argus, any flow will work if you modify the properties correctly.
# The idea is to get the appropriate files into a DB for time series analysis.

# This version includes the experation of keys
# use ttl to test existence
# set the amount of time in seconds to expire a key
# large networks may consume memory so start with 3 days or  expire at 432000 (5 days)
# if you have confidence, use 691200 that is 8 days
expire_time = 691200

import sys
import subprocess
import argparse
import time
import redis

options = None


def main():
        global options
        parser = argparse.ArgumentParser(description='Argus flow read to redis.')
        ''' File(s) or interface '''

        # files require the designation plus the path
        parser.add_argument('-f','--file',help='specifiy the file by path /path/to/file')
        # Interface requies a server and port parsed to work effectively
        parser.add_argument('-i', '--interface', help='specify remote argus and optional port number  server:port')
        args = parser.parse_args()
        print args

        if args.file == None and args.interface == None:
            print 'you must select file or interface'
            print '-f /path/to/argus/file'
            print '-i 127.0.0.1:561 and requires that argus is serving flows on that port'
            sys.exit(-1)

        # process the parsed arguments into a valid argus command
        if args.file != None:
	    command = "/usr/sbin/ra -nnr "+args.file+"  -c, -u -s stime saddr daddr dport - udp 2> /dev/null"

        if args.interface != None:
            command = "/usr/sbin/ra -nnS"+args.interface+" -c, -u -s stime saddr daddr dport - tcp and src syn 2> /dev/null"
        argus = subprocess.Popen(command,stdout=subprocess.PIPE,shell=True)    

	#redis
        r = redis.StrictRedis(host='localhost', port=6379, db=0)

        while True:
                argus.poll()                   
                line = argus.stdout.readline() 
                if line == '' or line == '\n':
                    print 'Finished'	    
                    sys.exit(1)
		elif line == 'Ra Version 3.0.6\n' or line == 'StartTime,SrcAddr,DstAddr,Dport\n':
		    print line
                else:
                    line = line[:-1]
                    fields = line.split(',')
		    #if fields[0] == 'StartTime':
		    ip_src = fields[1]
		    ip_dst = fields[2]
		    ip_dport = fields[3]
		    Fixtime = int(line[0:10])
		    UDate = time.gmtime(Fixtime)
		    working_date = str(UDate.tm_year)+str(UDate.tm_mon)+str(UDate.tm_mday)

		try:
		    quantset_multi = str(ip_src)+":"+str(ip_dst)+":"+str(ip_dport)+":multi"
		    quantset = str(ip_src)+":"+str(ip_dst)+":"+str(ip_dport)+":"+working_date
		    keyset_ipsrc = "ip_src:" + str(ip_src)
		    keyset_ipdst = "ip_dst:" + str(ip_dst)
		    r.sadd('SET:'+quantset, Fixtime)
		    r.sadd('SET:'+quantset_multi, Fixtime)
		    r.expire('SET:'+quantset, expire_time)
		    r.expire('SET:'+quantset, expire_time)
		    r.incr(keyset_ipsrc)
		    r.incr(keyset_ipdst)
		    r.expire(keyset_ipsrc, expire_time)
		    r.expire(keyset_ipsrc, expire_time)
		except:
		    print "Initial polling, error if this message repeats",line

if __name__ == '__main__':
        main()



