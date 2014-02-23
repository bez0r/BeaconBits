BeaconBits
==========

Beacon Bits is comprised of analytical scripts combined with a custom database that evaluate flow traffic for statistical uniformity over a given period of time.  The tool relies on some of the most common characteristics of infected host persisting in connection attempts to establish a connection, either to a remote host or set of host over a TCP network connection.  Useful to also identify automation, host behavior that is not driven by humans.

Network timing evaluation used to detect beacons, works with argus flow as the source

This is an updated version and migrated from the google page by the same name.

Beacon bits consist of python scripts used in conjunction with Argus flow files and a Redis database to analyze time series data for the presence of beacon behavior. Useful in detection of unconnected beacon activity that might be malicious.

See the orginal paper here: http://www.cert.org/flocon/2013/presentations/noble-kevin-statistical-analysis-flow-data.pdf

Details
-------

Beacon bits levages the session and timing information from flows (currently only argus) and uses a fast key value pair database for storage and analysis. Beaconbits is comprised of two scripts along with the other tools to present a list of beacon like behavior discovered in the analysis.



Requirements
------------

The current version works with Argus flows and Redis, both are required with the scrips to evaluate network traffic.

Requires Python 2.7.x

Argus, either collected to the interface or capture files. http://www.qosient.com/argus/downloads.shtml

Redis, currently set for a local instance and port. http://redis.io/download

Redis-py from here: https://github.com/andymccurdy/redis-py


This version writes to db1 only.

Author
------

terraplex gmail.com



