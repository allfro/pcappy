#!/usr/bin/env python

from ctypes import POINTER, byref
from socket import *
from struct import pack, unpack
from os import geteuid, name

from pcappy.constants import *
from pcappy.functions import *
from pcappy.types import *


__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PcapPy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

__all__ = [
    'PcapPy'
]


def _inet_ntoa(ip):
    return inet_ntop(AF_INET, pack('!L', htonl(ip)))


def _inet6_ntoa(ip):
    return inet_ntop(AF_INET6, ip)


def _inet_atoi(ip):
    return htonl(unpack('!L', inet_aton(ip))[0])


class PcapPyInterface(object):

    def __init__(self, pa):

        self.addresses = []
        self.name = pa.name
        self.description = pa.description or ''
        self.flags = pa.flags

        topaddr = pa.addresses

        while topaddr:
            topaddr = topaddr.contents

            self.addresses.append(
                dict(
                    addr=self._parseaddrs(topaddr.addr),
                    netmask=self._parseaddrs(topaddr.netmask),
                    broadaddr=self._parseaddrs(topaddr.broadaddr),
                    dstaddr=self._parseaddrs(topaddr.dstaddr)
                )
            )

            topaddr = topaddr.next


    def _parseaddrs(self, sa):

        if not sa:
            return
        sa = sa.contents
        if sa.sa.sa_family == AF_INET:
            return dict(
                len=sa.sin.sin_len,
                family=sa.sin.sin_family,
                port=sa.sin.sin_port,
                address=_inet_ntoa(sa.sin.sin_addr)
            )
        elif sa.sa.sa_family == AF_INET6:
            return dict(
                len=sa.sin6.sin6_len,
                port=sa.sin6.sin6_port,
                family=sa.sin6.sin6_family,
                flowinfo=sa.sin6.sin6_flowinfo,
                address=_inet6_ntoa(string_at(sa.sin6.sin6_addr, 16))
            )
        return dict(
            len=sa.sa.sa_len,
            family=sa.sa.sa_family,
            data=string_at(sa.sa.sa_data, sa.sa.sa_len)
        )

class PcapPyDumper(object):

    def __init__(self, pcap, filename):
        self._pcap = pcap
        self.filename = filename
        self._pd = pcap_dump_open(self._pcap._p, self.filename)

    def close(self):
        if self._pd:
            pcap_dump_close(self._pd)

    def tell(self):
        r = pcap_dump_ftell(self._pd)
        if r == -1:
            raise OSError(self._pcap.err)
        return r

    def flush(self):
        r = pcap_dump_flush(self._pd)
        if r == -1:
            raise OSError(self._pcap.err)

    def write(self, pkt_hdr, pkt_data):
        ph = pcap_pkthdr(
            ts=timeval(
                tv_sec=pkt_hdr['ts']['tv_sec'],
                tv_usec=pkt_hdr['ts']['tv_usec']
            ),
            caplen=pkt_hdr['caplen'],
            len=pkt_hdr['len']
        )
        pcap_dump(self._pd, byref(ph), pkt_data)

    dump = write

    @property
    def file(self):
        f = pcap_dump_file(self._pd)
        if not f:
            raise OSError(self._pcap.err)
        return PyFile_FromFile(f, self.filename, "wb", None)

    def __del__(self):
        self.close()


class PcapPyBpfProgram(object):

    def __init__(self, expr, opt, nm, **kwargs):
        self._expression = expr
        self._optimize = opt
        self._netmask = nm
        self._bpf = bpf_program()
        if 'pcap' in kwargs:
            if pcap_compile(kwargs['pcap']._p, byref(self._bpf), expr, opt, _inet_atoi(nm)) == -1:
                raise OSError(kwargs['pcap'].err)
        else:
            if pcap_compile(kwargs['snaplen'], kwargs['linktype'], byref(self._bpf), expr, opt, _inet_atoi(nm)) == -1:
                raise OSError(kwargs['pcap'].err)

    @property
    def expression(self):
        return self._expression

    @property
    def optimize(self):
        return self._optimize

    @property
    def netmask(self):
        return self._netmask

    mask = netmask

    def __del__(self):
        if self._bpf:
            pcap_freecode(byref(self._bpf))


class PcapPy(object):

    def __init__(self):
        self.errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        self.filename = None
        self._p = None
        self._bpf = None
        self.last = None

    def open_live(self, device, snaplen=64, promisc=1, to_ms=1000):
        self._p = pcap_open_live(device, snaplen, promisc, to_ms, byref(self.errbuf))
        self.filename = None
        if not self._p:
            raise OSError(self.errbuf.raw)

    def open_dead(self, linktype=LINKTYPE_ETHERNET, snaplen=64):
        self._p = pcap_open_dead(linktype, snaplen)
        self.filename = None
        if not self._p:
            raise OSError(self.errbuf.raw)

    def open_offline(self, file):
        self._p = pcap_open_offline(file, byref(self.errbuf))
        self.filename = file
        if not self._p:
            raise OSError(self.errbuf.raw)

    @property
    def nonblock(self):
        r = pcap_getnonblock(self._p, byref(self.errbuf))
        if r == -1:
            raise OSError(self.errbuf.raw)
        return r

    @nonblock.setter
    def nonblock(self, value):
        r = pcap_setnonblock(self._p, value, byref(self.errbuf))
        if r == -1:
            raise OSError(self.errbuf.raw)

    def findalldevs(self):
        devs = POINTER(pcap_if)()

        if pcap_findalldevs(byref(devs), byref(self.errbuf)) == -1:
            raise OSError(self.errbuf.raw)

        return self._parsedevs(devs)

    #    def findalldevs_ex(self, source, username='', password=''):
    #        ra = pcap_rmtauth()
    #        ra.type = RPCAP_RMTAUTH_PWD if username and password else RPCAP_RMTAUTH_NULL
    #        ra.username = username
    #        ra.password = password
    #
    #        devs = POINTER(pcap_if)()
    #
    #        if pcap_findalldevs_ex(source, byref(ra), byref(devs), byref(self.errbuf)) == -1:
    #            raise OSError(errbuf.raw)
    #
    #        return self._parsedevs(devs)

    def _parsedevs(self, devs):
        top = devs
        devices = []

        while top:
            top = top.contents
            devices.append(PcapPyInterface(top))
            top = top.next

        pcap_freealldevs(devs)

        return devices

    def _parse_entry(self, ph, pd):
        if platform == 'darwin':
            return dict(
                caplen=ph.caplen,
                len=ph.len,
                ts=dict(tv_usec=ph.ts.tv_usec, tv_sec=ph.ts.tv_sec),
                comments=string_at(ph.comments)
            ), string_at(pd, ph.caplen)

        return dict(
            caplen=ph.caplen,
            len=ph.len,
            ts=dict(tv_usec=ph.ts.tv_usec, tv_sec=ph.ts.tv_sec)
        ), string_at(pd, ph.caplen)


    def next_ex(self):
        ph = POINTER(pcap_pkthdr)()
        pd = POINTER(c_ubyte)()

        r = pcap_next_ex(self._p, byref(ph), byref(pd))

        if r in [0, -2]:
            return None
        elif r == -1:
            raise OSError(self.err)

        return self._parse_entry(ph.contents, pd)

#    next = next_ex
    def next(self):
        ph = pcap_pkthdr()
        pd = pcap_next(self._p, byref(ph))

        if not pd:
            return None

        return self._parse_entry(ph, pd)

    @property
    def snapshot(self):
        return pcap_snapshot(self._p)

    def dump_open(self, filename):
        return PcapPyDumper(self, filename)

    def loop(self, cnt, callback, user):
        return self._setup_handler(pcap_loop, cnt, callback, user)

    def dispatch(self, cnt, callback, user):
        return self._setup_handler(pcap_dispatch, cnt, callback, user)

    def _setup_handler(self, looper, cnt, callback, user):
        def _loop_callback(user, ph, pd):
            ph, pd = self._parse_entry(ph.contents, pd)
            callback(user.contents.value, ph, pd)

        r = looper(self._p, cnt, pcap_handler(_loop_callback), byref(py_object(user)))
        if r == -1:
            raise OSError(self.err)
        return r

    def breakloop(self):
        pcap_breakloop(self._p)

    def lookupdev(self):
        r = pcap_lookupdev(byref(self.errbuf))
        if not r:
            raise OSError(self.errbuf.raw)
        return r

    @property
    def stats(self):
        ps = pcap_stat()

        if pcap_stats(self._p, byref(ps)):
            raise OSError(self.err)

        if platform == 'nt':
            return dict(
                ps_recv=ps.ps_recv,
                ps_drop=ps.ps_drop,
                ps_ifdrop=ps.ps_ifdrop,
                bs_capt=ps.bs_capt
            )

        return dict(
            ps_recv=ps.ps_recv,
            ps_drop=ps.ps_drop,
            ps_ifdrop=ps.ps_ifdrop
        )

    @property
    def datalink(self):
        r = pcap_datalink(self._p)
        if r == -1:
            raise OSError(self.err)
        return r

    @datalink.setter
    def datalink(self, value):
        if pcap_set_datalink(self._p, value) == -1:
            raise OSError(self.err)

    def list_datalinks(self):
        dlt_buf = POINTER(c_int)()

        r = pcap_list_datalinks(self._p, byref(dlt_buf))

        if r == -1:
            raise OSError(self.err)

        dlt_buf = cast(dlt_buf, POINTER(c_int * r)).contents

        return [dlt_buf[i] for i in range(0, r)]

    def geterr(self):
        return self.err

    @property
    def err(self):
        return pcap_geterr(self._p)

    @property
    def file(self):
        if self.filename is None:
            return None
        f = pcap_file(self._p)
        return PyFile_FromFile(f, self.filename, "rb", None)

    def datalink_val_to_name(self, val):
        r = pcap_datalink_val_to_name(val)
        if not r:
            raise OSError(self.err)
        return r

    def datalink_name_to_val(self, name):
        r = pcap_datalink_name_to_val(name)
        if r == -1:
            raise OSError(self.err)
        return r

    def datalink_val_to_description(self, val):
        r = pcap_datalink_val_to_description(val)
        if not val:
            raise OSError(self.err)
        return r

    def sendpacket(self, data):
        r = pcap_sendpacket(self._p, data, len(data))
        if r == -1:
            raise OSError(self.err)
        return r

    def lookupnet(self, device):
        netp = c_uint32()
        maskp = c_uint32()
        r = pcap_lookupnet(device, byref(netp), byref(maskp), byref(self.errbuf))
        if r == -1:
            raise OSError(self.err)
        return _inet_ntoa(netp.value), _inet_ntoa(maskp.value)

    def compile(self, expr, optimize=1, mask='0.0.0.0'):
        return PcapPyBpfProgram(expr, optimize, mask, pcap=self)

    @property
    def filter(self):
        return self._bpf

    @filter.setter
    def filter(self, value):
        if isinstance(value, basestring):
            self._bpf = self.compile(value)

        if pcap_setfilter(self._p, byref(self._bpf._bpf)) == -1:
            raise OSError(self.err)

    @classmethod
    def compile_nopcap(cls, snaplen, linktype, expr, optimize=1, mask='0.0.0.0'):
        return PcapPyBpfProgram(expr, optimize, mask, linktype=linktype, snaplen=snaplen)

    @property
    def is_swapped(self):
        return pcap_is_swapped(self._p) == 1

    @property
    def minor_version(self):
        return pcap_minor_version(self._p)

    @property
    def major_version(self):
        return pcap_major_version(self._p)

    @property
    def lib_version(self):
        return pcap_lib_version(self._p)

    def __del__(self):
        if self._p:
            pcap_close(self._p)