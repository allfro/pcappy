#!/usr/bin/env python

from ctypes import *
from sys import platform

from pcappy.constants import PCAP_ERRBUF_SIZE


__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PcapPy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'


class pcap_t(Structure):
    pass


class pcap_stat(Structure):
    if platform == 'nt':
        _fields_ = [
            ('ps_recv', c_uint),
            ('ps_drop', c_uint),
            ('ps_ifdrop', c_uint),
            ('bs_capt', c_uint)
        ]
    else:
        _fields_ = [
            ('ps_recv', c_uint),
            ('ps_drop', c_uint),
            ('ps_ifdrop', c_uint)
        ]


class timeval(Structure):
    _fields_ = [
        ('tv_sec', c_long),
        ('tv_usec', c_long)
    ]


class pcap_pkthdr(Structure):
    if platform == 'darwin':
        _fields_ = [
            ('ts', timeval),
            ('caplen', c_uint32),
            ('len', c_uint32),
            ('comments', (c_char * 256))
        ]
    else:
        _fields_ = [
            ('ts', timeval),
            ('caplen', c_uint32),
            ('len', c_uint32)
        ]


class pcap_sf(Structure):
    _fields = [
        ('rfile', c_void_p),
        ('swapped', c_int),
        ('hdrsize', c_int),
        ('version_major', c_int),
        ('version_minor', c_int),
        ('base', POINTER(c_ubyte))
    ]


class pcap_md(Structure):
    if platform.startswith('linux'):
        _fields = [
            ('stat', pcap_stat),
            ('use_bpf', c_int),
            ('TotPkts', c_ulong),
            ('TotAccepted', c_ulong),
            ('TotDrops', c_ulong),
            ('TotMissed', c_long),
            ('OrigMissed', c_long),
            ('sock_packet', c_int),
            ('readlen', c_int),
            ('timeout', c_int),
            ('clear_promisc', c_int),
            ('cooked', c_int),
            ('lo_ifindex', c_int),
            ('*device', c_char),
            ('*next', pcap_t),
        ]
    else:
        _fields = [
            ('stat', pcap_stat),
            ('use_bpf', c_int),
            ('TotPkts', c_ulong),
            ('TotAccepted', c_ulong),
            ('TotDrops', c_ulong),
            ('TotMissed', c_long),
            ('OrigMissed', c_long)
        ]


class bpf_insn(Structure):
    _fields_ = [
        ('code', c_ushort),
        ('jt', c_ubyte),
        ('jf', c_ubyte),
        ('k', c_int)
    ]


class bpf_program(Structure):
    _fields_ = [
        ('bf_len', c_uint),
        ('bf_insns', POINTER(bpf_insn))
    ]


class sockaddr_in(Structure):
    _pack_ = 1
    _fields_ = [
        ('sin_len', c_ubyte),
        ('sin_family', c_ubyte),
        ('sin_port', c_ushort),
        ('sin_addr', c_uint32),
        ('sin_zero', c_ubyte * 8)
    ]


class sockaddr_in6(Structure):
    _pack_ = 1
    _fields_ = [
        ('sin6_len', c_ubyte),
        ('sin6_family', c_ubyte),
        ('sin6_port', c_ushort),
        ('sin6_flowinfo', c_uint32),
        ('sin6_addr', c_ubyte * 16),
        ('sin6_scope_id', c_uint32)
    ]


class sockaddr_sa(Structure):
    _pack_ = 1
    _fields_ = [
        ('sa_len', c_ubyte),
        ('sa_family', c_ubyte),
        ('sa_data', c_char * 14)
    ]


class sockaddr(Union):
    _pack_ = 1
    _fields_ = [
        ('sa', sockaddr_sa),
        ('sin', sockaddr_in),
        ('sin6', sockaddr_in6)
        #        ('sa_family', c_ushort),
        #        ('sa_data', c_char * 14)
    ]


class pcap_addr(Structure):
    _pack_ = 1


pcap_addr._fields_ = [
    ('next', POINTER(pcap_addr)),
    ('addr', POINTER(sockaddr)),
    ('netmask', POINTER(sockaddr)),
    ('broadaddr', POINTER(sockaddr)),
    ('dstaddr', POINTER(sockaddr))
]


class pcap_if(Structure):
    _pack_ = 1


pcap_if._fields_ = [
    ('next', POINTER(pcap_if)),
    ('name', c_char_p),
    ('description', c_char_p),
    ('addresses', POINTER(pcap_addr)),
    ('flags', c_uint)
]


pcap_t._fields_ = [
    ('fd', c_int),
    ('snapshot', c_int),
    ('linktype', c_int),
    ('tzoff', c_int),
    ('offset', c_int),
    ('pcap_sf', pcap_sf),
    ('pcap_md', pcap_md),
    ('bufsize', c_int),
    ('buffer', POINTER(c_ubyte)),
    ('bp', POINTER(c_ubyte)),
    ('cc', c_int),
    ('pkt', c_char_p),
    ('fcode', bpf_program),
    ('errbuf', (c_char * PCAP_ERRBUF_SIZE))
]


class pcap_rmtauth(Structure):
    _fields_ = [
        ('type', c_int),
        ('username', c_char_p),
        ('password', c_char_p)
    ]

class pcap_dumper(Structure):
    pass

pcap_handler = CFUNCTYPE(None, POINTER(py_object), POINTER(pcap_pkthdr), POINTER(c_ubyte))

# Ripped from http://svn.python.org/projects/ctypes/trunk/ctypeslib/ctypeslib/contrib/pythonhdr.py
try:
    class FILE(Structure):
        pass
    FILE_ptr = POINTER(FILE)
    CLOSEFUNC = CFUNCTYPE(c_int, FILE_ptr)

    PyFile_FromFile = pythonapi.PyFile_FromFile
    PyFile_FromFile.restype = py_object
    PyFile_FromFile.argtypes = [
        FILE_ptr,
        c_char_p,
        c_char_p,
        c_void_p
    ]

    PyFile_AsFile = pythonapi.PyFile_AsFile
    PyFile_AsFile.restype = FILE_ptr
    PyFile_AsFile.argtypes = [py_object]
except AttributeError:
    del FILE_ptr


