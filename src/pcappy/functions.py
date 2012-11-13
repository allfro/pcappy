#!/usr/bin/env python

from ctypes import *
from ctypes.util import find_library

from types import *


__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PcapPy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.2'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'


_pcap = cdll.LoadLibrary(find_library('pcap'))


pcap_functions = globals()


def load_func(name, restype=None, argtypes=[]):
    try:
        pcap_functions[name] = getattr(_pcap, name)
        pcap_functions[name].argtypes = argtypes
        pcap_functions[name].restype = restype
    except AttributeError:
        def _pcap_unsupported(*args, **kwargs):
            raise NotImplementedError('This version of libpcap does not appear to be compiled with %s support.' % repr(name))
        pcap_functions[name] = _pcap_unsupported


load_func('pcap_lookupdev', c_char_p, [ c_char_p ])


load_func('pcap_lookupnet', c_int, [ c_char_p, c_uint32_p, c_uint32_p, c_char_p ])


load_func('pcap_create', pcap_t_ptr, [ c_char_p, c_char_p ])


load_func('pcap_set_snaplen', c_int, [ pcap_t_ptr, c_int ])


load_func('pcap_set_promisc', c_int, [ pcap_t_ptr, c_int ])


load_func('pcap_can_set_rfmon', c_int, [ pcap_t_ptr ])


load_func('pcap_set_rfmon', c_int, [ pcap_t_ptr, c_int ])


load_func('pcap_set_timeout', c_int, [ pcap_t_ptr, c_int ])


load_func('pcap_set_buffer_size', c_int, [ pcap_t_ptr, c_int ])


load_func('pcap_activate', c_int, [ pcap_t_ptr ])


load_func('pcap_apple_set_exthdr', c_int, [ pcap_t_ptr, c_int ]) # Todo


load_func('pcap_open_live', pcap_t_ptr, [c_char_p, c_int, c_int, c_int, c_char_p])


load_func('pcap_open_dead', pcap_t_ptr, [ c_int, c_int ])


load_func('pcap_open_offline', pcap_t_ptr, [ c_char_p, c_char_p ])


load_func('pcap_hopen_offline', pcap_t_ptr, [ c_int_p, c_char_p ]) # Todo


load_func('pcap_fopen_offline', pcap_t_ptr, [ FILE_ptr, c_char_p ])


load_func('pcap_close', argtypes=[ pcap_t_ptr ])


load_func('pcap_loop', c_int, [ pcap_t_ptr, c_int, pcap_handler, py_object_p ])


load_func('pcap_dispatch', c_int, [ pcap_t_ptr, c_int, pcap_handler, py_object_p ])


load_func('pcap_next', c_ubyte_p, [ pcap_t_ptr, pcap_pkthdr_ptr ])


load_func('pcap_next_ex', c_int, [ pcap_t_ptr, POINTER(pcap_pkthdr_ptr), POINTER(c_ubyte_p) ])


load_func('pcap_breakloop', argtypes=[ pcap_t_ptr ])


load_func('pcap_stats', c_int, [ pcap_t_ptr, pcap_stat_ptr ] )


load_func('pcap_setfilter', c_int, [ pcap_t_ptr, bpf_program_ptr ])


load_func('pcap_setdirection', c_int, [ pcap_t_ptr, c_int ])


load_func('pcap_getnonblock', c_int, [pcap_t_ptr, c_char_p])


load_func('pcap_setnonblock', c_int, [pcap_t_ptr, c_int, c_char_p])


load_func('pcap_inject', c_int, [ pcap_t_ptr, c_char_p, c_size_t ])


load_func('pcap_sendpacket', c_int, [ pcap_t_ptr, c_char_p, c_int ])


load_func('pcap_statustostr', c_char_p, [ c_int ])


load_func('pcap_strerror', c_char_p, [ c_int ])


load_func('pcap_geterr', c_char_p, [ pcap_t_ptr ])


load_func('pcap_perror', argtypes=[ pcap_t_ptr, c_char_p ])


load_func('pcap_compile', c_int, [ pcap_t_ptr, bpf_program_ptr, c_char_p, c_int, c_uint32 ])


load_func('pcap_compile_nopcap', c_int, [ c_int, c_int, bpf_program_ptr, c_char_p, c_int, c_uint32 ])


load_func('pcap_freecode', argtypes=[ bpf_program_ptr ])


load_func('pcap_offline_filter', c_int, [ bpf_program_ptr, pcap_pkthdr_ptr, c_char_p ]) # Todo


load_func('pcap_datalink', c_int, [ pcap_t_ptr ])


load_func('pcap_datalink_ext', c_int, [ pcap_t_ptr ])


load_func('pcap_list_datalinks', c_int, [ pcap_t_ptr, POINTER(c_int_p) ])


load_func('pcap_set_datalink', c_int, [ pcap_t_ptr, c_int ])


load_func('pcap_free_datalinks', argtypes=[ c_int_p ])


load_func('pcap_datalink_name_to_val', c_int, [ c_char_p ])


load_func('pcap_datalink_val_to_name', c_char_p, [ c_int ])


load_func('pcap_datalink_val_to_description', c_char_p, [ c_int ])


load_func('pcap_snapshot', c_int, [ pcap_t_ptr ])


load_func('pcap_is_swapped', c_int, [ pcap_t_ptr ])


load_func('pcap_major_version', c_int, [ pcap_t_ptr ])


load_func('pcap_minor_version', c_int, [ pcap_t_ptr ])


load_func('pcap_file', FILE_ptr, [ pcap_t_ptr ])


load_func('pcap_fileno', c_int, [ pcap_t_ptr ])


load_func('pcap_dump_open', pcap_dumper_t_ptr, [ pcap_t_ptr, c_char_p ])


load_func('pcap_dump_fopen', pcap_dumper_t_ptr, [ pcap_t_ptr, FILE_ptr ])


load_func('pcap_dump_file', FILE_ptr, [ pcap_dumper_t_ptr ])


load_func('pcap_dump_ftell', c_long, [ pcap_dumper_t_ptr ])


load_func('pcap_dump_flush', c_int, [ pcap_dumper_t_ptr ])


load_func('pcap_dump_close', argtypes=[ pcap_dumper_t_ptr ])


load_func('pcap_dump', argtypes=[ pcap_dumper_t_ptr, pcap_pkthdr_ptr, c_char_p ])


load_func('pcap_ng_dump_open', pcap_dumper_t_ptr, [ pcap_t_ptr, c_char_p ])


load_func('pcap_ng_dump_fopen', pcap_dumper_t_ptr, [ pcap_t_ptr, FILE_ptr ])


load_func('pcap_ng_dump', argtypes=[ pcap_dumper_t_ptr, pcap_pkthdr_ptr, c_char_p ])


load_func('pcap_ng_dump_close', argtypes=[ pcap_dumper_t_ptr ])


load_func('pcap_findalldevs', c_int, [ POINTER(pcap_if_t_ptr), c_char_p ])


load_func('pcap_findalldevs_ex', c_int, [ c_char_p, pcap_rmtauth_ptr, POINTER(pcap_if_t_ptr), c_char_p ])


load_func('pcap_freealldevs', argtypes=[ pcap_if_t_ptr ])


load_func('pcap_lib_version', c_char_p)


load_func('bpf_filter', c_uint, [ bpf_insn_ptr, c_char_p, c_uint, c_uint ]) # Todo


load_func('bpf_validate', c_int, [ bpf_insn_ptr, c_int ]) # Todo


load_func('bpf_image', c_char_p, [ bpf_insn_ptr, c_int ]) # Todo


load_func('bpf_dump', argtypes=[ bpf_program_ptr, c_int ]) # Todo


load_func('pcap_setbuff', c_int, [ pcap_t_ptr, c_int ]) # Todo


load_func('pcap_setmode', c_int, [ pcap_t_ptr, c_int ]) # Todo


load_func('pcap_setmintocopy', c_int, [ pcap_t_ptr, c_int ]) # Todo


load_func('pcap_stats_ex', c_int, [ pcap_t_ptr, pcap_stat_ex_ptr ]) # Todo


load_func('pcap_set_wait', [ pcap_t_ptr, yield_, c_int ]) # Todo


load_func('pcap_mac_packets', c_ulong) # Todo


load_func('pcap_get_selectable_fd', c_int, [ pcap_t_ptr ])



