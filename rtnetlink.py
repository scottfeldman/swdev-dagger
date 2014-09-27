#!/usr/bin/env python

from socket import NETLINK_ROUTE, AF_INET, AF_INET6, AF_BRIDGE
from string import printable
from ipaddr import *
from ctypes import *
from netlink import *
import logging

logger = logging.getLogger(__name__)

#
# from /usr/include/linux/rtnetlink.h
#

RTMGRP_LINK = 0x1
RTMGRP_NEIGH = 0x4
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV4_ROUTE = 0x40
RTMGRP_IPV6_IFADDR = 0x100
RTMGRP_IPV6_ROUTE = 0x400

RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_GETLINK = 18
RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_GETADDR = 22
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_GETNEIGH = 30

# Definitions used in routing table administration.

class Nlmsg(Structure):

    def _stringify(self):
        return string_at(addressof(self), sizeof(self))

    def __eq__(self, other):
        return self._stringify() == other._stringify() and \
            self.__dict__ == other.__dict__

    def to_rta(self):
        return Rtattr.from_address(addressof(self) + NLMSG_ALIGN(sizeof(self)))

    def pack_extra(self, extra, addr):
        memmove(addr, addressof(extra), sizeof(extra))
        return NLMSG_ALIGN(sizeof(extra))

    def pack_rtas(self, rtas, addr):
        total_len = 0
        for rta_type, value in rtas.iteritems():
            rta = Rtattr.from_address(addr)
            rta.rta_type = rta_type
            pack_fn = self.rta_fn(rta_type)
            rta_len = NLMSG_ALIGN(pack_fn(rta, value))
            total_len += rta_len
            addr += rta_len
        return total_len

    def unpack_rtas(self, which_ones=[]):
        len = self.nlh.nlmsg_len - NLMSG_LENGTH(sizeof(self))
        rta = self.to_rta()
        rtas = {}
        while RTA_OK(rta, len):
            rta_type = rta.rta_type
            if not which_ones or rta_type in which_ones:
                unpack_fn = self.rta_fn(rta_type)
                rtas[rta_type] = unpack_fn(rta)
            len, rta = RTA_NEXT(rta, len)
        return rtas

    def dump_rtas(self):
        rtas = self.unpack_rtas()
        for type, value in rtas.iteritems():
            print "rta", type, ":", value

    class _IPv6Addr(BigEndianStructure):
        _fields_ = [
            ('upper', c_uint64),
            ('lower', c_uint64),
        ]

    class _IPv4Addr(BigEndianStructure):
        _fields_ = [
            ('addr', c_uint32),
        ]

    def rta_uint8(self, rta, value=None):
        data = RTA_DATA(rta)
        if value:
            c_uint8.from_address(data).value = value
            rta.rta_len = RTA_LENGTH(sizeof(c_uint8))
            return rta.rta_len
	else:
            return c_uint8.from_address(data).value

    def rta_uint32(self, rta, value=None):
        data = RTA_DATA(rta)
        if value:
            c_uint32.from_address(data).value = value
            rta.rta_len = RTA_LENGTH(sizeof(c_uint32))
            return rta.rta_len
	else:
            return c_uint32.from_address(data).value

    def rta_string(self, rta, value=None):
        data = RTA_DATA(rta)
        if value:
            s = create_string_buffer(value)
            memmove(data, addressof(s), len(value))
            rta.rta_len = RTA_LENGTH(len(value))
            return rta.rta_len
        else:
            return c_char_p(data).value

    def rta_addr(self, rta, value=None):
        data = RTA_DATA(rta)
        if value:
            if isinstance(value, IPv4Address):
                self._IPv4Addr.from_address(data).addr = value._ip
                rta.rta_len = RTA_LENGTH(sizeof(self._IPv4Addr))
            elif isinstance(value, IPv6Address):
                addr = self._IPv6Addr.from_address(data)
                addr.upper = value._ip >> 64
                addr.lower = value._ip & 0xffffffffffffffff
                rta.rta_len = RTA_LENGTH(sizeof(self._IPv6Addr))
            else:
                assert(False)
            return rta.rta_len
        else:
            if RTA_PAYLOAD(rta) == 4:
                addr = c_uint32.__ctype_be__.from_address(data).value
                addr = IPv4Address(addr)
            else:
                addr = self._IPv6Addr.from_address(data)
                addr = IPv6Address((addr.upper << 64) + addr.lower)
            return addr

    def rta_uint8_array(self, rta, value=None):
        if value:
            assert(False)
        else:
            data = RTA_DATA(rta)
            array = (c_uint8 * RTA_PAYLOAD(rta))()
            memmove(array, data, RTA_PAYLOAD(rta))
            return array

    def rta_uint32_array(self, rta, value=None):
        if value:
            assert(False)
        else:
            data = RTA_DATA(rta)
            size = RTA_PAYLOAD(rta) / sizeof(c_uint32)
            array = (c_uint32 * size)()
            memmove(array, data, RTA_PAYLOAD(rta))
            return array

    def rta_multipath(self, rta, value=None):
        # XXX implement this
        return None

    def rta_wtf(self, rta, value=None):
        return None

    def rta_none(self, rta, value=None):
        return None

    def rta_fn(self, rta_type):
        return None

# rtm_type

RTN_UNSPEC = 0
RTN_UNICAST = 1            # Gateway or direct route
RTN_LOCAL = 2              # Accept locally
RTN_BROADCAST = 3          # Accept locally as broadcast,
                           # send as broadcast
RTN_ANYCAST = 4            # Accept locally as broadcast,
                           # but send as unicast
RTN_MULTICAST = 5          # Multicast route
RTN_BLACKHOLE = 6          # Drop
RTN_UNREACHABLE = 7        # Destination is unreachable
RTN_PROHIBIT = 8           # Administratively prohibited
RTN_THROW = 9              # Not in this table
RTN_NAT = 10               # Translate this address
RTN_XRESOLVE = 11          # Use external resolver
RTN_MAX = 11

# rtm_protocol

RTPROT_UNSPEC = 0
RTPROT_REDIRECT = 1     # Route installed by ICMP redirects;
                        # not used by current IPv4
RTPROT_KERNEL = 2       # Route installed by kernel
RTPROT_BOOT = 3         # Route installed during boot
RTPROT_STATIC = 4       # Route installed by administrator

# Values of protocol >= RTPROT_STATIC are not interpreted by kernel;
# they are just passed from user and back as is.
# It will be used by hypothetical multiple routing daemons.
# Note that protocol values should be standardized in order to
# avoid conflicts.

RTPROT_GATED = 8       # Apparently, GateD
RTPROT_RA = 9          # RDISC/ND router advertisements
RTPROT_MRT = 10        # Merit MRT
RTPROT_ZEBRA = 11      # Zebra
RTPROT_BIRD = 12       # BIRD
RTPROT_DNROUTED = 13   # DECnet routing daemon
RTPROT_XORP = 14       # XORP
RTPROT_NTK = 15        # Netsukuku
RTPROT_DHCP = 16       # DHCP client

# rtm_scope

# Really it is not scope, but sort of distance to the destination.
# NOWHERE are reserved for not existing destinations, HOST is our
# local addresses, LINK are destinations, located on directly attached
# link and UNIVERSE is everywhere in the Universe.

# Intermediate values are also possible f.e. interior routes
# could be assigned a value between UNIVERSE and LINK.

RT_SCOPE_UNIVERSE = 0
# User defined values
RT_SCOPE_SITE = 200
RT_SCOPE_LINK = 253
RT_SCOPE_HOST = 254
RT_SCOPE_NOWHERE=255

# rtm_flags

RTM_F_NOTIFY = 0x100   # Notify user of route change
RTM_F_CLONED = 0x200   # This route is cloned
RTM_F_EQUALIZE = 0x400 # Multipath equalizer: NI
RTM_F_PREFIX = 0x800   # Prefix addresses

# Reserved table identifiers

RT_TABLE_UNSPEC = 0
# User defined values
RT_TABLE_COMPAT = 252
RT_TABLE_DEFAULT = 253
RT_TABLE_MAIN = 254
RT_TABLE_LOCAL = 255
RT_TABLE_MAX = 0xFFFFFFFF

# Generic structure for encapsulation of optional route information.
# It is reminiscent of sockaddr, but with sa_family replaced
# with attribute type.

class Rtattr(Structure):

    _fields_ = [
        ('rta_len', c_uint16),
        ('rta_type', c_uint16),
    ]

# Routing message attributes

RTA_UNSPEC = 0
RTA_DST = 1
RTA_SRC = 2
RTA_IIF = 3
RTA_OIF = 4
RTA_GATEWAY = 5
RTA_PRIORITY = 6
RTA_PREFSRC = 7
RTA_METRICS = 8
RTA_MULTIPATH = 9
RTA_PROTOINFO = 10        # no longer used
RTA_FLOW = 11
RTA_CACHEINFO = 12
RTA_SESSION = 13          # no longer used
RTA_MP_ALGO = 14          # no longer used 
RTA_TABLE = 15
RTA_MAX = 15

# Macros to handle rtattributes

RTA_ALIGNTO = 4
def RTA_ALIGN(len):
    return (len + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1)
def RTA_OK(rta, len):
    return len >= sizeof(Rtattr) and \
        rta.rta_len >= sizeof(Rtattr) and \
        rta.rta_len <= len
def RTA_NEXT(rta, len):
    cur = RTA_ALIGN(rta.rta_len)
    rta = Rtattr.from_address(addressof(rta) + cur)
    return len - cur, rta
def RTA_LENGTH(len):
    return len + RTA_ALIGN(sizeof(Rtattr))
def RTA_SPACE(len):
    return RTA_ALIGN(RTA_LENGTH(len))
def RTA_DATA(rta):
    return addressof(rta) + RTA_LENGTH(0)
def RTA_PAYLOAD(rta):
    return rta.rta_len - RTA_LENGTH(0)

RTNH_F_DEAD = 1         # Nexthop is dead (used by multipath)
RTNH_F_PERVASIVE = 2    # Do recursive gateway lookup
RTNH_F_ONLINK = 4       # Gateway is forced on link

# Reserved table identifiers

RT_TABLE_UNSPEC = 0
# User defined values
RT_TABLE_COMPAT = 252
RT_TABLE_DEFAULT = 253
RT_TABLE_MAIN = 254
RT_TABLE_LOCAL = 255
RT_TABLE_MAX = 0xFFFFFFFF

class Rtmsg(Nlmsg):

    _fields_ = [
        ('rtm_family', c_uint8),
        ('rtm_dst_len', c_uint8),
        ('rtm_src_len', c_uint8),
        ('rtm_tos', c_uint8),
        ('rtm_table', c_uint8),
        ('rtm_protocol', c_uint8),
        ('rtm_scope', c_uint8),
        ('rtm_type', c_uint8),
        ('rtm_flags', c_uint32),
    ]

    _table_str = {
        RT_TABLE_UNSPEC: "unspecified",
        RT_TABLE_COMPAT: "compat",
        RT_TABLE_DEFAULT: "default",
        RT_TABLE_MAIN: "main",
        RT_TABLE_LOCAL: "local",
    }

    _proto_str = {
        RTPROT_UNSPEC: "none",
        RTPROT_REDIRECT: "redirect",
        RTPROT_KERNEL: "kernel",
        RTPROT_BOOT: "boot",
        RTPROT_STATIC: "static",
        RTPROT_GATED: "gated",
        RTPROT_RA: "ra",
        RTPROT_MRT: "mrtmrt",
        RTPROT_ZEBRA: "zebra",
        RTPROT_BIRD: "bird",
        RTPROT_DNROUTED: "dnrouted",
        RTPROT_XORP: "xorp",
        RTPROT_NTK: "ntk",
        RTPROT_DHCP: "dhcp",
    }

    _scope_str = {
        RT_SCOPE_UNIVERSE: "universe",
        RT_SCOPE_SITE: "site",
        RT_SCOPE_LINK: "link",
        RT_SCOPE_HOST: "host",
        RT_SCOPE_NOWHERE: "nowhere",
    }

    _type_str = {
        RTN_UNSPEC: "unspecified",
        RTN_UNICAST: "unicast",
        RTN_LOCAL: "local",
        RTN_BROADCAST: "broadcast",
        RTN_ANYCAST: "anycast",
        RTN_MULTICAST: "multicast",
        RTN_BLACKHOLE: "blackhole",
        RTN_UNREACHABLE: "unreachable",
        RTN_PROHIBIT: "prohibit",
        RTN_THROW: "throw",
        RTN_NAT: "nat",
        RTN_XRESOLVE: "xresolve",
    }

    def dump(self):
        print 'rtm_family', self.rtm_family
        print 'rtm_dst_len', self.rtm_dst_len
        print 'rtm_src_len', self.rtm_src_len
        print 'rtm_tos', self.rtm_tos
        print 'rtm_table', self._table_str.get(self.rtm_table, self.rtm_table)
        print 'rtm_protocol', self._proto_str.get(self.rtm_protocol)
        print 'rtm_scope', self._scope_str.get(self.rtm_scope)
        print 'rtm_type', self._type_str.get(self.rtm_type)
        print 'rtm_flags 0x%08x' % self.rtm_flags

    def rta_fn(self, rta_type):
        fns = {
            RTA_DST: self.rta_addr,
            RTA_SRC: self.rta_addr,
            RTA_IIF: self.rta_uint32,
            RTA_OIF: self.rta_uint32,
            RTA_GATEWAY: self.rta_addr,
            RTA_PRIORITY: self.rta_uint32,
            RTA_PREFSRC: self.rta_addr,
            RTA_METRICS: self.rta_uint32_array,
            RTA_MULTIPATH: self.rta_multipath,
            RTA_PROTOINFO: self.rta_none,
            RTA_FLOW: self.rta_uint32,
            RTA_CACHEINFO: self.rta_none,
            RTA_SESSION: self.rta_none,
            RTA_MP_ALGO: self.rta_none,
            RTA_TABLE: self.rta_uint32,
        }
        return fns.get(rta_type)

class Rtgenmsg(Nlmsg):

    _fields_ = [
        ('rtgen_family', c_uint8),
    ]

    def dump(self):
        print 'rtgen_family', self.rtgen_family

# New extended info filters for IFLA_EXT_MASK
RTEXT_FILTER_VF = (1 << 0)

# passes link level specific information, not dependent
# on network protocol.

IFLA_UNSPEC = 0
IFLA_ADDRESS = 1
IFLA_BROADCAST = 2
IFLA_IFNAME = 3
IFLA_MTU = 4
IFLA_LINK = 5
IFLA_QDISC = 6
IFLA_STATS = 7
IFLA_COST = 8
IFLA_PRIORITY = 9
IFLA_MASTER = 10
IFLA_WIRELESS = 11          # Wireless Extension event - see wireless.h
IFLA_PROTINFO = 12          # Protocol specific information for a link
IFLA_TXQLEN = 13
IFLA_MAP = 14
IFLA_WEIGHT = 15
IFLA_OPERSTATE = 16
IFLA_LINKMODE = 17
IFLA_LINKINFO = 18
IFLA_NET_NS_PID = 19
IFLA_IFALIAS = 20
IFLA_NUM_VF = 21            # Number of VFs if device is SR-IOV PF
IFLA_VFINFO_LIST = 22
IFLA_STATS64 = 23
IFLA_VF_PORTS = 24
IFLA_PORT_SELF = 25
IFLA_AF_SPEC = 26
IFLA_GROUP = 27             # Group the device belongs to
IFLA_NET_NS_FD = 28
IFLA_EXT_MASK = 29          # Extended info mask, VFs, etc
IFLA_MAX = 29

class Ifinfomsg(Nlmsg):

    _fields_ = [
        ('ifi_family', c_uint8),
        ('__ifi_pad', c_uint8),
        ('ifi_type', c_uint16),      # ARPHRD_*
        ('ifi_index', c_int32),      # Link index
        ('ifi_flags', c_uint32),     # IFF_* flags
        ('ifi_change', c_uint32),    # IFF_* change mask
    ]

    def dump(self):
        print 'ifi_family', self.ifi_family
        print 'ifi_type', self.ifi_type
        print 'ifi_index', self.ifi_index
        print 'ifi_flags 0x%08x' % self.ifi_flags
        print 'ifi_change 0x%08x' % self.ifi_change

    def rta_fn(self, rta_type):
        fns = {
            IFLA_UNSPEC: self.rta_wtf,
            IFLA_ADDRESS: self.rta_uint8_array,
            IFLA_BROADCAST: self.rta_uint8_array,
            IFLA_IFNAME: self.rta_string,
            IFLA_MTU: self.rta_uint32,
            IFLA_LINK: self.rta_uint32,
            IFLA_QDISC: self.rta_string,
            IFLA_STATS: self.rta_none,
            IFLA_COST: self.rta_none,
            IFLA_PRIORITY: self.rta_none,
            IFLA_MASTER: self.rta_uint32,
            IFLA_WIRELESS: self.rta_none,
            IFLA_PROTINFO: self.rta_none,
            IFLA_TXQLEN: self.rta_uint32,
            IFLA_MAP: self.rta_none,
            IFLA_WEIGHT: self.rta_uint32,
            IFLA_OPERSTATE: self.rta_uint8,
            IFLA_LINKMODE: self.rta_uint8,
            IFLA_LINKINFO: self.rta_none,
            IFLA_NET_NS_PID: self.rta_uint32,
            IFLA_IFALIAS: self.rta_string,
            IFLA_NUM_VF: self.rta_uint32,
            IFLA_VFINFO_LIST: self.rta_none,
            IFLA_STATS64: self.rta_none,
            IFLA_VF_PORTS: self.rta_none,
            IFLA_PORT_SELF: self.rta_none,
            IFLA_AF_SPEC: self.rta_none,
            IFLA_GROUP: self.rta_none,
            IFLA_NET_NS_FD: self.rta_none,
            IFLA_EXT_MASK: self.rta_none,
        }
        return fns.get(rta_type)

# passes address specific information

# Important comment:
# IFA_ADDRESS is prefix address, rather than local interface address.
# It makes no difference for normally configured broadcast interfaces,
# but for point-to-point IFA_ADDRESS is DESTINATION address,
# local address is supplied in IFA_LOCAL attribute.

IFA_UNSPEC = 0
IFA_ADDRESS = 1
IFA_LOCAL = 2
IFA_LABEL = 3
IFA_BROADCAST = 4
IFA_ANYCAST = 5
IFA_CACHEINFO = 6
IFA_MULTICAST = 7
IFA_MAX = 7

class Ifaddrmsg(Nlmsg):

    _fields_ = [
        ('ifa_family', c_uint8),
        ('ifa_prefixlen', c_uint8), # The prefix length
        ('ifa_flags', c_uint8),     # Flags
        ('ifa_scope', c_uint8),     # Address scope
        ('ifa_index', c_uint32),    # Link index
    ]

    _family_str = {
        AF_INET: "inet",
        AF_INET6: "inet6",
    }

    def dump(self):
        print 'ifa_family', self.ifa_family
        print 'ifa_prefixlen', self.ifa_prefixlen
        print 'ifa_flags 0x%02x' % self.ifa_flags
        print 'ifa_scope', self.ifa_scope
        print 'ifa_index', self.ifa_index

    def rta_fn(self, rta_type):
        fns = {
            IFA_ADDRESS: self.rta_addr,
            IFA_LOCAL: self.rta_addr,
            IFA_LABEL: self.rta_string,
            IFA_BROADCAST: self.rta_addr,
            IFA_ANYCAST: self.rta_addr,
            IFA_CACHEINFO: self.rta_none,
            IFA_MULTICAST: self.rta_addr,
        }
        return fns.get(rta_type)

#
# from /usr/include/linux/neighbour.h
#

NDA_UNSPEC = 0
NDA_DST = 1
NDA_LLADDR = 2
NDA_CACHEINFO = 3
NDA_PROBES = 4
NDA_VLAN = 5
NDA_PORT = 6
NDA_VNI = 7
NDA_IFINDEX = 8
NDA_MASTER = 9
NDA_MAX = 9

# Neighbor Cache Entry Flags

NTF_USE = 0x01
NTF_PROXY = 0x08   # == ATF_PUBL
NTF_ROUTER = 0x80
NTF_SELF = 0x02
NTF_MASTER = 0x04

# Neighbor Cache Entry States

NUD_INCOMPLETE = 0x01
NUD_REACHABLE = 0x02
NUD_STALE = 0x04
NUD_DELAY = 0x08
NUD_PROBE = 0x10
NUD_FAILED = 0x20
# Dummy states
NUD_NOARP = 0x40
NUD_PERMANENT = 0x80
NUD_NONE = 0x00

class Ndmsg(Nlmsg):

    _fields_ = [
        ('ndm_family', c_uint8),
        ('ndm_pad1', c_uint8),
        ('ndm_pad2', c_uint16),
        ('ndm_ifindex', c_uint32),
        ('ndm_state', c_uint16),
        ('ndm_flags', c_uint8),
        ('ndm_type', c_uint8),
    ]

    def dump(self):
        print 'ndm_family', self.ndm_family
        print 'ndm_ifindex', self.ndm_ifindex
        print 'ndm_state', self.ndm_state
        print 'ndm_flags 0x%02x' % self.ndm_flags
        print 'ndm_type', self.ndm_type

    def rta_fn(self, rta_type):
        fns = {
            NDA_DST: self.rta_addr,
            NDA_LLADDR: self.rta_uint8_array,
            NDA_CACHEINFO: self.rta_none,
            NDA_PROBES: self.rta_none,
            NDA_VLAN: self.rta_none,
            NDA_PORT: self.rta_none,
            NDA_VNI: self.rta_none,
            NDA_IFINDEX: self.rta_uint32,
            NDA_MASTER: self.rta_uint32,
        }
        return fns.get(rta_type)

class RtNetlinkError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)
        logger.error(message)

class RtNetlink(Netlink):

    def __init__(self, pid):
        Netlink.__init__(self, pid, NETLINK_ROUTE)

    _rt_nlmsg_type_str = {
        RTM_NEWROUTE: "RTM_NEWROUTE",
        RTM_DELROUTE: "RTM_DELROUTE",
        RTM_NEWLINK: "RTM_NEWLINK",
        RTM_DELLINK: "RTM_DELLINK",
        RTM_GETLINK: "RTM_GETLINK",
        RTM_NEWADDR: "RTM_NEWADDR",
        RTM_DELADDR: "RTM_DELADDR",
        RTM_NEWNEIGH: "RTM_NEWNEIGH",
        RTM_DELNEIGH: "RTM_DELNEIGH",
    }

    def _hexdump(self, buf):
        while buf:
            chunk = buf[:16]
            buf = buf[16:]
            nums = ["%02x" % c for c in chunk]
            txt = [chr(c) if chr(c) in printable[:-5] else '.' for c in chunk]
            print " ".join(nums).ljust(48), "".join(txt)

    def dump(self, nlh):
        nlmsg = self.nlmsg(nlh)
        print
        self._hexdump(self.sendbuf[:nlh.nlmsg_len])
        print
        nlh.dump()
        print
        nlmsg.dump()
        print
        nlmsg.dump_rtas()

    def nlmsg(self, nlh):
        nlmsg_struct = {
            RTM_NEWROUTE: Rtmsg,
            RTM_DELROUTE: Rtmsg,
            RTM_GETROUTE: Rtmsg,
            RTM_NEWLINK: Ifinfomsg,
            RTM_DELLINK: Ifinfomsg,
            RTM_GETLINK: Rtgenmsg,
            RTM_NEWADDR: Ifaddrmsg,
            RTM_DELADDR: Ifaddrmsg,
            RTM_GETADDR: Rtgenmsg,
            RTM_NEWNEIGH: Ndmsg,
            RTM_DELNEIGH: Ndmsg,
            RTM_GETNEIGH: Rtgenmsg,
        }
        nldata = NLMSG_DATA(nlh)
        nlmsg = nlmsg_struct[nlh.nlmsg_type].from_address(nldata)
        nlmsg.nlh = nlh
        return nlmsg

    def _nl_cb(self, nlh):
        #print "nl cb", self._rt_nlmsg_type_str[nlh.nlmsg_type]

        if nlh.nlmsg_type in self._cbs:

            nlmsg = self.nlmsg(nlh)

            # validate nl length
            if nlh.nlmsg_len - NLMSG_LENGTH(sizeof(nlmsg)) < 0:
                raise RtNetlinkError("invalid nl length")

            self._cbs[nlh.nlmsg_type](nlh, nlmsg)

    def bind(self, groups, cbs):
        self._cbs = cbs
        Netlink.bind(self, groups, self._nl_cb)

    def request(self, nlmsg_type, flags, extra, rtas={}):

        nlh = Nlmsghdr.from_buffer(self.sendbuf)
        nlh_p = addressof(nlh)

        seq = self.seq
        pid = self.pid

        nlh.nlmsg_len = NLMSG_HDRLEN()
        nlh.nlmsg_type = nlmsg_type
        nlh.nlmsg_flags = flags
        nlh.nlmsg_pid = pid
        nlh.nlmsg_seq = seq

        nlmsg = self.nlmsg(nlh)

        nlh.nlmsg_len += nlmsg.pack_extra(extra, nlh_p + nlh.nlmsg_len)
        nlh.nlmsg_len += nlmsg.pack_rtas(rtas, nlh_p + nlh.nlmsg_len)

        #self.dump(nlh)
        self.sendall(string_at(nlh_p, nlh.nlmsg_len))
        self.seq += 1

        token = (pid, seq)
        return token
