#!/usr/bin/env python

from ctypes import POINTER, pointer
from socket import *
from struct import pack, unpack
from binascii import hexlify

from pcappy.constants import *
from pcappy.functions import *


__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PcapPy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.2'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

__all__ = [
    'PcapPyLive',
    'PcapPyOffline',
    'PcapPyDead',
    'open_offline',
    'open_dead',
    'open_live',
    'PcapPyException'
]


def _inet_ntoa(ip):
    return inet_ntop(AF_INET, pack('!L', htonl(ip)))


def _inet6_ntoa(ip):
    return inet_ntop(AF_INET6, ip)


def _inet_atoi(ip):
    return htonl(unpack('!L', inet_aton(ip))[0])


class PcapPyException(Exception):
    pass


class PcapPyInterface(object):

    def __init__(self, pa):

        self._addresses = []
        self._name = pa.name
        self._description = pa.description or ''
        self._flags = pa.flags

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

    @property
    def addresses(self):
        return self._addresses

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @property
    def flags(self):
        return self._flags

    def _parsemac(self, mac):
        return ':'.join([ hexlify(i).zfill(2) for i in mac ])


    def _parseaddrs(self, sa):

        if not sa:
            return
        sa = sa.contents

        if sa.sa.sa_family == AF_LINK:
            return dict(
                sdl_len=sa.sdl.sdl_len,
                sdl_family=sa.sdl.sdl_family,
                sdl_index=sa.sdl.sdl_index,
                sdl_type=sa.sdl.sdl_type,
                sdl_nlen=sa.sdl.sdl_nlen,
                sdl_alen=sa.sdl.sdl_alen,
                sdl_slen=sa.sdl.sdl_slen,
                sdl_data=self._parsemac(string_at(byref(sa.sdl.sdl_data, sa.sdl.sdl_nlen), sa.sdl.sdl_alen))
            )
        elif sa.sa.sa_family == AF_PACKET:
            return dict(
                sll_family=sa.sll.sll_family,
                sll_protocol=sa.sll.sll_protocol,
                sll_ifindex=sa.sll.sll_ifindex,
                sll_hatype=sa.sll.sll_hatype,
                sll_pkttype=sa.sll.sll_pkttype,
                sll_halen=sa.sll.sll_halen,
                sll_data=self._parsemac(string_at(byref(sa.sll.sll_data), sa.sll.sll_halen))
            )
        elif sa.sa.sa_family == AF_INET:
            if platform == 'darwin':
                return dict(
                    len=sa.sin.sin_len,
                    family=sa.sin.sin_family,
                    port=sa.sin.sin_port,
                    address=_inet_ntoa(sa.sin.sin_addr)
                )
            else:
                return dict(
                    family=sa.sin.sin_family,
                    port=sa.sin.sin_port,
                    address=_inet_ntoa(sa.sin.sin_addr)
                )
        elif sa.sa.sa_family == AF_INET6:
            if platform == 'darwin':
                return dict(
                    len=sa.sin6.sin6_len,
                    port=sa.sin6.sin6_port,
                    family=sa.sin6.sin6_family,
                    flowinfo=sa.sin6.sin6_flowinfo,
                    address=_inet6_ntoa(string_at(sa.sin6.sin6_addr, 16)),
                    scope_id=sa.sin6.sin6_scope_id
                )
            else:
                return dict(
                    port=sa.sin6.sin6_port,
                    family=sa.sin6.sin6_family,
                    flowinfo=sa.sin6.sin6_flowinfo,
                    address=_inet6_ntoa(string_at(sa.sin6.sin6_addr, 16)),
                    scope_id=sa.sin6.sin6_scope_id
                )
        if platform == 'darwin':
            return dict(
                len=sa.sa.sa_len,
                family=sa.sa.sa_family,
                data=string_at(sa.sa.sa_data, sa.sa.sa_len)
            )
        else:
            return dict(
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
            raise PcapPyException(self._pcap.err)
        return r

    def flush(self):
        r = pcap_dump_flush(self._pd)
        if r == -1:
            raise PcapPyException(self._pcap.err)

    def write(self, pkt_hdr, pkt_data):
        ph = pcap_pkthdr(
            ts=timeval(
                tv_sec=pkt_hdr['ts']['tv_sec'],
                tv_usec=pkt_hdr['ts']['tv_usec']
            ),
            caplen=pkt_hdr['caplen'],
            len=pkt_hdr['len']
        )
        pcap_dump(self._pd, pointer(ph), pkt_data)

    dump = write

    @property
    def file(self):
        f = pcap_dump_file(self._pd)
        if not f:
            raise PcapPyException(self._pcap.err)
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
            if pcap_compile(kwargs['pcap']._p, pointer(self._bpf), expr, opt, _inet_atoi(nm)) == -1:
                raise PcapPyException(kwargs['pcap'].err)
        else:
            if pcap_compile_nopcap(kwargs['snaplen'], kwargs['linktype'], pointer(self._bpf), expr, opt, _inet_atoi(nm)) == -1:
                raise PcapPyException(kwargs['pcap'].err)

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
            pcap_freecode(pointer(self._bpf))


def open_live(device, snaplen=64, promisc=1, to_ms=1000):
    return PcapPyLive(device, snaplen, promisc, to_ms)


def open_dead(linktype=LINKTYPE_ETHERNET, snaplen=64):
    return PcapPyDead(linktype, snaplen)


def open_offline(file):
    return PcapPyOffline(file)


class PcapPyBase(object):

    _is_base = True

    def __init__(self):
        if self._is_base:
            raise Exception('Cannot initialize base class. Use PcapPyLive, PcapPyDead, or PcapPyOffline instead.')
        self.errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        self._p = None
        self._bpf = None

    def _parsedevs(self, devs):
        top = devs
        devices = []

        while top:
            top = top.contents
            devices.append(PcapPyInterface(top))
            top = top.next

        pcap_freealldevs(devs)

        return devices

    def findalldevs(self):
        devs = pcap_if_t_ptr()

        if pcap_findalldevs(pointer(devs), c_char_p((addressof(self.errbuf)))) == -1:
            raise PcapPyException(self.errbuf.raw)

        return self._parsedevs(devs)

    def findalldevs_ex(self, source, username='', password=''):
        ra = pcap_rmtauth()
        ra.type = RPCAP_RMTAUTH_PWD if username and password else RPCAP_RMTAUTH_NULL
        ra.username = username
        ra.password = password

        devs = POINTER(pcap_if)()

        if pcap_findalldevs_ex(source, pointer(ra), pointer(devs), c_char_p((addressof(self.errbuf)))) == -1:
            raise PcapPyException(errbuf.raw)

        return self._parsedevs(devs)

    def geterr(self):
        return self.err

    def lookupdev(self):
        r = pcap_lookupdev(c_char_p((addressof(self.errbuf))))
        if not r:
            raise PcapPyException(self.errbuf.raw)
        return r

    def list_datalinks(self):
        dlt_buf = c_int_p()

        r = pcap_list_datalinks(self._p, pointer(dlt_buf))

        if r == -1:
            raise PcapPyException(self.err)

        dlt_buf_a = cast(dlt_buf, POINTER(c_int * r)).contents

        l = [ dlt_buf_a[i] for i in range(0, r) ]

        pcap_free_datalinks(dlt_buf)

        return l

    def datalink_val_to_name(self, val):
        r = pcap_datalink_val_to_name(val)
        if not r:
            raise PcapPyException(self.err)
        return r

    def datalink_name_to_val(self, name):
        r = pcap_datalink_name_to_val(name)
        if r == -1:
            raise PcapPyException(self.err)
        return r

    def datalink_val_to_description(self, val):
        r = pcap_datalink_val_to_description(val)
        if not val:
            raise PcapPyException(self.err)
        return r

    def lookupnet(self, device):
        netp = c_uint32()
        maskp = c_uint32()

        r = pcap_lookupnet(
            device,
            pointer(netp),
            pointer(maskp),
            c_char_p(addressof(self.errbuf))
        )
        if r == -1:
            raise PcapPyException(self.errbuf.raw)
        return _inet_ntoa(netp.value), _inet_ntoa(maskp.value)

    def compile(self, expr, optimize=1, mask='0.0.0.0'):
        return PcapPyBpfProgram(expr, optimize, mask, pcap=self)

    def dump_open(self, filename):
        return PcapPyDumper(self, filename)

    @classmethod
    def compile_nopcap(cls, snaplen=64, linktype=LINKTYPE_ETHERNET, expr='', optimize=1, mask='0.0.0.0'):
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

    @property
    def err(self):
        return pcap_geterr(self._p)

    @property
    def datalink(self):
        r = pcap_datalink(self._p)
        if r == -1:
            raise PcapPyException(self.err)
        return r

    @datalink.setter
    def datalink(self, value):
        if pcap_set_datalink(self._p, value) == -1:
            raise PcapPyException(self.err)

    @property
    def snapshot(self):
        return pcap_snapshot(self._p)

    snaplen = snapshot

    def __del__(self):
        if self._p:
            pcap_close(self._p)


class PcapPyDead(PcapPyBase):

    _is_base = False

    def __init__(self, linktype=LINKTYPE_ETHERNET, snaplen=64):
        super(PcapPyDead, self).__init__()
        self._p = pcap_open_dead(linktype, snaplen)
        if not self._p:
            raise PcapPyException(self.errbuf.raw)


class PcapPyAlive(PcapPyBase):

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

    def _setup_handler(self, looper, cnt, callback, user):
        def _loop_callback(user, ph, pd):
            ph, pd = self._parse_entry(ph.contents, pd)
            callback(user.contents.value, ph, pd)

        r = looper(self._p, cnt, pcap_handler(_loop_callback), pointer(py_object(user)))
        if r == -1:
            raise PcapPyException(self.err)
        return r

    def loop(self, cnt, callback, user):
        return self._setup_handler(pcap_loop, cnt, callback, user)

    def dispatch(self, cnt, callback, user):
        return self._setup_handler(pcap_dispatch, cnt, callback, user)

    def breakloop(self):
        pcap_breakloop(self._p)

    def next_ex(self):
        ph = pcap_pkthdr_ptr()
        pd = c_ubyte_p()

        r = pcap_next_ex(self._p, pointer(ph), pointer(pd))

        if r in [0, -2]:
            return None
        elif r == -1:
            raise PcapPyException(self.err)

        return self._parse_entry(ph.contents, pd)

    def next(self):
        ph = pcap_pkthdr()
        pd = pcap_next(self._p, pointer(ph))

        if not pd:
            return None

        return self._parse_entry(ph, pd)

    @property
    def nonblock(self):
        r = pcap_getnonblock(self._p, c_char_p((addressof(self.errbuf))))
        if r == -1:
            raise PcapPyException(self.errbuf.raw)
        return r

    @nonblock.setter
    def nonblock(self, value):
        r = pcap_setnonblock(self._p, value, c_char_p((addressof(self.errbuf))))
        if r == -1:
            raise PcapPyException(self.errbuf.raw)

    @property
    def stats(self):
        ps = pcap_stat()

        if pcap_stats(self._p, pointer(ps)):
            raise PcapPyException(self.err)

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
    def filter(self):
        return self._bpf

    @filter.setter
    def filter(self, value):
        if isinstance(value, basestring):
            self._bpf = self.compile(value)
        else:
            self._bpf = value
        if pcap_setfilter(self._p, pointer(self._bpf._bpf)) == -1:
            raise PcapPyException(self.err)


class PcapPyOffline(PcapPyAlive):

    _is_base = False

    def __init__(self, file_):
        super(PcapPyOffline, self).__init__()
        if isinstance(file_, file):
            self._p = pcap_fopen_offline(PyFile_AsFile(file_), c_char_p((addressof(self.errbuf))))
        else:
            self._p = pcap_open_offline(file_, c_char_p((addressof(self.errbuf))))
        self.filename = file_
        if not self._p:
            raise PcapPyException(self.errbuf.raw)

    @property
    def file(self):
        f = pcap_file(self._p)
        return PyFile_FromFile(f, self.filename, "rb", None)

    @property
    def fileno(self):
        return pcap_fileno(self._p)


class PcapPyLive(PcapPyAlive):

    _is_base = False

    def __init__(self, device, snaplen=64, promisc=1, to_ms=1000):
        super(PcapPyLive, self).__init__()
        self._p = pcap_open_live(device, snaplen, promisc, to_ms, c_char_p((addressof(self.errbuf))))
        if not self._p:
            raise PcapPyException(self.errbuf.raw)

    def sendpacket(self, data):
        r = pcap_sendpacket(self._p, data, len(data))
        if r == -1:
            raise PcapPyException(self.err)
        return r

    def inject(self, data):
        r = pcap_inject(self._p, data, len(data))
        if r == -1:
            raise PcapPyException(self.err)
        return r