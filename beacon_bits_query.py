# !/usr/bin/env python
# http://code.google.com/p/beaconbits/
#
# This is the query tool, it is used to query all the values stored in the redis database.

# This code is released under license GPL3


import sys
import argparse
import datetime
import time
import math
import redis
import formatter

options = None      #default for options
acceptable = ['all','top','All','Top']
worklist = []
tempset = []
mvalue = False
toplist1 = ()
toplist = []





## The values below are flexible and offer some guidelines for adjustmet

# magic values bring attention to specific intervals of beacon by changing to the color of the graph from default yellow to orange
# add or remove as needed, the values are in seconds
magic_values = 15,29,30,31,59,60,61,89,90,91,119,120,121,239,240,241,299,300,301,400,514,600,720,900,1200,1600,1799,1800,2400,3600,4200,43200,86400


#  minimal count to consider for beaconbits
# Do not set below 3, ideal is proablaby 12
set_minvalue = 12

# Maximum number for consideration
# large sets cause performance issues
# this threshold is set at 30000 for demo purposes but you might want to set really high for a first run
# set low, to 5000 if you have confidence in checking through netflow or other top analytical methods
set_maxvalue = 1000

# This is the minimal duration estimate from first to last packet within the dataset as calculated.
# 900 seconds in 15 minutes, aggressive would be 300 (900)
set_duration_estimate = 900

# ALL allowance for highest visitor count
# think of this number as the highest number of infected internal host that might go to a single external host
# This variable estimates how many host might be connecting to a given IP by counting connections per internal host
# this is only an estimate by taking the total attempts by any given host against the total for all host
# this assumes that popular sites get more host visiting, say more then 5, 10, or 100
# This assumes also that attackers don't completely own your network and are below a threshold for beacons
# say 5 internal host beaconed and were compromised, thus set it to 6 or 7 to be safe
set_visitor = 5

# TOP value for highest compensated variance
# componsated variance is the maximum acceptable variance for consideration
# setting to 10 really gives the most idealistic beacons
# setting to 300 is fairly broad but useful while evaluating effectiveness
set_comp_var = 35


# TOP values for compvar
# compansated variance divided by time gives a factor that allows for tolerance that is quite different then standard deviation
# set to 140 to get a large factor of beacons, and divide by half as needed, probably don't want to drop below 35
# if you find the top 
set_compvar_time_factor = 35

# minimal mean to consider in seconds
# want to avoid mean values below 15 seconds for example, depends on the network but certainly 5 seconds would be decent
set_minimal_mean = 5

# destination port removal
not_port = ['25']

# An interesting factor is taking the componsated variance and dividing it by the number of seconds in the duration estimate


''' a few embedded algorithms that will be moved out as selectable at the command line'''
def compensated_variance(data):
    # sourced from HTTP://en.wikipedia.org/w/index.php?title=Algorithms_for_calculating_variance
    n = 0
    sum1 = 0
    for x in data:
        n = n + 1
        sum1 = sum1 + int(x)
    mean = sum1/n
 
    sum2 = 0
    sum3 = 0
    for x in data:
        sum2 = sum2 + (int(x) - mean)**2
        sum3 = sum3 + (int(x) - mean)
    variance = (sum2 - sum3**2/n)/(n - 1)
    return variance

def online_variance(data): 
    n = 0
    mean = 0
    M2 = 0
 
    for x in data:
        n = n + 1
        delta = int(x) - mean
        mean = mean + delta/n
        M2 = M2 + delta*(int(x) - mean)
 
    variance_n = M2/n
    variance = M2/(n - 1)
    return (variance, variance_n)

def population_fix(data):
    goods=[]
    diff = int(data[1]) - int(data[0])
    for each in data:
	    workvalue = int(each) - int(diff)
	    goods.append(workvalue)
	    diff = each
    goods.pop(0)
    return(goods)

def pdns_Lookup(ip_value):
    pdns = redis.StrictRedis(host='localhost', port=6379, db=0)
    result = pdns.hget('IP:'+ip_value, 'name')
    return(result)

def quick_mean(data):
    goods=[]
    diff = int(data[1]) - int(data[0])
    for each in data:
	workvalue = int(each) - int(diff)
	goods.append(workvalue)
	diff = each
    goods.pop(0)
    #print goods
    mean = 0
    for each in goods:
	mean += int(each)
    return(mean/len(goods))


def scatter_plot(data):
    import numpy as np
    import matplotlib.pyplot as plt
    import random
    # LABEL,MEAN(seconds),VARIANCE,COUNT
    plt.ylabel('Variance',fontsize=20)
    plt.xlabel('Mean in Seconds', fontsize=20)
    plt.title('Beacon Bits')
    plt.grid(True)
    base_color = 'yellow'
    for each in data:
	label = str(each[1])+":"+str(each[2]) # dst IP address
	x = each[5]     # mean
	y = each[7]     # variance
	z = each[4]*2    # count
	#print x,y,z

	if x in magic_values:
	    base_color = 'orange'
	else:
	    base_color = 'yellow'
	
        spot = random.randrange(-40,40,10)
        plt.scatter(x,y,z,cmap = plt.get_cmap('Spectral'))
	plt.annotate(label, xy = (x, y), xytext = (spot, spot),
            textcoords = 'offset points', ha = 'right', va = 'bottom',
            bbox = dict(boxstyle = 'round,pad=0.5', fc = base_color, alpha = 0.5),
            arrowprops = dict(arrowstyle = '->', connectionstyle = 'arc3,rad=0'))

    plt.show()
    pass


def main():
        global options
        
        parser = argparse.ArgumentParser(description='Beacon bits is a time series analyzer for beacons. Requires Redis server running on default port and writes to db0.')

        args = parser.parse_args()
        print args

	print 'This version only prints top output'
        print 'src_ip','         dst_ip','        dst_port','set_date','pair_count','mean','duration','var','src_count','dst_count','visitors'


        '''open a connection to the local redis database'''        
        r = redis.StrictRedis(host='localhost', port=6379, db=1)

        roundone = r.keys('SET:*')
        for each in roundone:
                newcount = r.scard(each)
                if newcount >= set_minvalue and newcount <= set_maxvalue:
                    worklist.append(each)


        for each in worklist:
                tab_queue = 0
                cummulative_value = 0
                visitors = 0
		dst_count = 0
		
                pair_count = r.scard(each)
                if pair_count <= 3:  # don't work on values without at least 4
                    print 'low pair_count', each,'count:',pair_count
                    break

		# this is the set we are working with
                tempset = r.sort(each, alpha=True)

		mean = quick_mean(tempset)
		#print int(mean)

                sets_sub = each.split(':')
                set_src_ip = sets_sub[1]
                set_dst_ip = sets_sub[2]
                set_dst_port = sets_sub[3]
                set_date = sets_sub[4]
                src_count = r.get('ip_src:'+set_src_ip)
                dst_count = r.get('ip_dst:'+set_dst_ip)


                if int(tempset[1]) - int(tempset[0]) >0: # ensure second value minus the first is gretter then zero as a test
                    compvar = compensated_variance(population_fix(tempset))  #get the variance of the population
                else:
                    print 'failure for', each
                    break
		duration_est = (mean * pair_count) / 60
		if dst_count !=  None and pair_count != None:
		    visitors =   int(dst_count) / int(pair_count)
		if compvar <= set_comp_var and mean >= set_minimal_mean and set_dst_port not in not_port:
		    toplist2 = (set_src_ip,set_dst_ip,set_dst_port,set_date,pair_count,mean,duration_est,compvar,src_count,dst_count,visitors)
		    if toplist2 not in toplist:
			toplist.append(toplist2)
		else:
		    #r.delete(each)
		    pass

		# flush key_value
		key_value = []

        ''' printing top values'''
        toplist.sort()
        for each in toplist:
            dom1 = "lookup value" #pdns_Lookup(each[1])
            print "{0:15} {1:15} {2:7} {3:8} {4:6} {5:6} {6:4} {7:8} {8:6} {9:6} {10:6} {11:16}".format(each[0],each[1],each[2],each[3],each[4],each[5],each[6],each[7],each[8],each[9],each[10],dom1)
        print "Finished"
	
	''' scatter plot '''
	scatter_plot(toplist)
	
if __name__ == '__main__':
        main()
        
