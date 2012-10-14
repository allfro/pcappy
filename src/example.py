#!/usr/bin/env python

from pcappy import PcapPyOffline, open_offline
from sys import argv

if not argv[1:]:
    print 'usage: %s <dump.pcap>' % argv[0]
    exit(-1)

# Open the file
p = open_offline(argv[1])

# or this instead: p = PcapPyOffline(argv[1])


# Parse only HTTP traffic
p.filter = 'tcp and port 80'


def gotpacket(d, hdr, data):
    print d, hdr, repr(data)
    d['count'] += 1

# pass in some random parameters to loop()'s callback. Can be any python object you want!
d = {'label': 'HTTP', 'count': 0}

# Parameters are count, callback, user params
p.loop(-1, gotpacket, d)
