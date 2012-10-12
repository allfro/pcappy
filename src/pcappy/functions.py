#!/usr/bin/env python

from ctypes import *
from ctypes.util import find_library

from pcappy.types import *


__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PcapPy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'


_pcap = cdll.LoadLibrary(find_library('pcap'))


pcap_open_live = _pcap.pcap_open_live
pcap_open_live.restype = POINTER(pcap_t)


pcap_open_dead = _pcap.pcap_open_dead
pcap_open_dead.restype = POINTER(pcap_t)


pcap_open_offline = _pcap.pcap_open_offline
pcap_open_offline.restype = POINTER(pcap_t)


pcap_dump_open = _pcap.pcap_dump_open
pcap_dump_open.restype = POINTER(pcap_dumper)


pcap_getnonblock = _pcap.pcap_getnonblock


pcap_setnonblock = _pcap.pcap_setnonblock


pcap_findalldevs = _pcap.pcap_findalldevs


pcap_freealldevs = _pcap.pcap_freealldevs


pcap_lookupdev = _pcap.pcap_lookupdev
pcap_lookupdev.restype = c_char_p


pcap_lookupnet = _pcap.pcap_lookupnet


pcap_dispatch = _pcap.pcap_dispatch


pcap_loop = _pcap.pcap_loop


pcap_next = _pcap.pcap_next
pcap_next.restype = POINTER(c_ubyte)
pcap_next.argtypes = [POINTER(pcap_t), POINTER(pcap_pkthdr)]


pcap_next_ex = _pcap.pcap_next_ex


pcap_breakloop = _pcap.pcap_breakloop


pcap_sendpacket = _pcap.pcap_sendpacket


pcap_dump = _pcap.pcap_dump


pcap_dump_ftell = _pcap.pcap_dump_ftell


pcap_compile = _pcap.pcap_compile


pcap_compile_nopcap = _pcap.pcap_compile_nopcap


pcap_setfilter = _pcap.pcap_setfilter


pcap_freecode = _pcap.pcap_freecode


pcap_datalink = _pcap.pcap_datalink


pcap_list_datalinks = _pcap.pcap_list_datalinks


pcap_set_datalink = _pcap.pcap_set_datalink


pcap_datalink_name_to_val = _pcap.pcap_datalink_name_to_val


pcap_datalink_val_to_name = _pcap.pcap_datalink_val_to_name
pcap_datalink_val_to_name.restype = c_char_p


pcap_datalink_val_to_description = _pcap.pcap_datalink_val_to_description
pcap_datalink_val_to_description.restype = c_char_p


pcap_snapshot = _pcap.pcap_snapshot


pcap_is_swapped = _pcap.pcap_is_swapped


pcap_major_version = _pcap.pcap_major_version


pcap_minor_version = _pcap.pcap_minor_version


pcap_file = _pcap.pcap_file
pcap_file.restype = FILE_ptr


pcap_stats = _pcap.pcap_stats


pcap_perror = _pcap.pcap_perror


pcap_geterr = _pcap.pcap_geterr
pcap_geterr.restype = c_char_p


#pcap_strerr = _pcap.pcap_strerr


pcap_lib_version = _pcap.pcap_lib_version
pcap_lib_version.restype = c_char_p


pcap_close = _pcap.pcap_close


pcap_dump_file = _pcap.pcap_dump_file
pcap_dump_file.restype = FILE_ptr

pcap_dump_flush = _pcap.pcap_dump_flush


pcap_dump_close = _pcap.pcap_dump_close

#pcap_findalldevs_ex = _pcap.pcap_findalldevs_ex




