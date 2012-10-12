# PcapPy

PcapPy is a Python wrapper for libpcap purely written in Python. That's right! No need to compile anything using ugly
wrapper frameworks like Cython, Pyrex or SWIG (yuck!). Using the pure power of ctypes, PcapPy will give you that warm
fuzzy feeling at night.

# Installation

Simple:

`sudo easy_install pcappy`

Winning!

# Example

Sure why not:

```python
#!/usr/bin/env python

from pcap import PcapPy
from sys import argv

if not argv[1:]:
    print 'usage: %s <dump.pcap>' % argv[0]
    exit(-1)


p = PcapPy()

# Open the file
p.open_offline(argv[1])

# Parse only HTTP traffic
p.filter = 'tcp and port 80'


def gotpacket(d, hdr, data):
    print d, hdr, repr(data)
    d['count'] += 1

# pass in some random parameters to loop()'s callback. Can be any python object you want!
d = {'label': 'HTTP', 'count': 0}

# Parameters are count, callback, user params
p.loop(-1, gotpacket, d)
```

Now run it:

`python example.py dump.pcap`

Et Voila! You're off to the races!

# Questions?

We've got answers: drop me a line @ndouba or < ndouba at gmail dot com > on twitter!