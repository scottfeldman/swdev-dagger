#!/usr/bin/env python

from socket import AF_UNSPEC, AF_INET, AF_INET6, AF_BRIDGE
from rtnetlink import *
import logging

logger = logging.getLogger(__name__)

class KCacheIface(Ifinfomsg):

    def __init__(self, ifi, flags, ifname, mac_addr, mtu, master):
        memmove(addressof(self), addressof(ifi), sizeof(ifi))
        self.flags = flags
        self.ifname = ifname
        self.mac_addr = mac_addr
        self.mtu = mtu
        self.master = master
        self.stale = False

    def __eq__(self, other):
        return (string_at(addressof(self), sizeof(self)) == \
            string_at(addressof(other), sizeof(other))) and \
            self.flags == other.flags and \
            self.ifname == other.ifname and \
            string_at(self.mac_addr) == string_at(other.mac_addr) and \
            self.mtu == other.mtu and \
            self.master == other.master

class KCacheAddr(Ifaddrmsg):

    def __init__(self, ifa, addr):
        memmove(addressof(self), addressof(ifa), sizeof(ifa))
        self.addr = addr
        self.stale = False

    def __eq__(self, other):
        return (string_at(addressof(self), sizeof(self)) == \
            string_at(addressof(other), sizeof(other))) and \
            self.addr == other.addr

class KCachePath(Rtmsg):

    def __init__(self, rtm, oif, prefsrc, gateway, priority):
        memmove(addressof(self), addressof(rtm), sizeof(rtm))
        self.oif = oif 
        self.prefsrc = prefsrc
        self.gateway = gateway
        self.priority = priority
        self.stale = False

    def __eq__(self, other):
        return (string_at(addressof(self), sizeof(self)) == \
            string_at(addressof(other), sizeof(other))) and \
            self.oif == other.oif and \
            self.prefsrc == other.prefsrc and \
            self.gateway == other.gateway and \
            self.priority == other.priority

class KCacheNeigh(Ndmsg):

    def __init__(self, ndm, lladdr, master):
        memmove(addressof(self), addressof(ndm), sizeof(ndm))
        self.lladdr = lladdr
        self.master = master
        self.stale = False

    def __eq__(self, other):
        return (string_at(addressof(self), sizeof(self)) == \
            string_at(addressof(other), sizeof(other))) and \
            string_at(addressof(self.lladdr), sizeof(self.lladdr))  == \
            string_at(addressof(other.lladdr), sizeof(other.lladdr)) and \
            self.master == other.master

class KCacheError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)
        logger.error(message)

class KCache(RtNetlink):

    def __init__(self, pid, family=AF_UNSPEC,
        types=[RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH],
        filters={}, notifiers={}):

        RtNetlink.__init__(self, pid)

        if family not in [AF_UNSPEC, AF_INET, AF_INET6, AF_BRIDGE]:
            raise KCacheError("family %d not supported" % family)

        self.cache_family = family
        self.types = types
        self.filters = filters
        self.notifiers = notifiers 

        groups = 0
        if RTM_GETLINK in types:
            groups |= RTMGRP_LINK
        if RTM_GETADDR in types:
            if family in [AF_UNSPEC, AF_INET]:
                groups |= RTMGRP_IPV4_IFADDR
            if family in [AF_UNSPEC, AF_INET6]:
                groups |= RTMGRP_IPV6_IFADDR
        if RTM_GETROUTE in types:
            if family in [AF_UNSPEC, AF_INET]:
                groups |= RTMGRP_IPV4_ROUTE
            if family in [AF_UNSPEC, AF_INET6]:
                groups |= RTMGRP_IPV6_ROUTE
        if RTM_GETNEIGH in types:
            groups |= RTMGRP_NEIGH

        self.bind(groups, self._cbs())

        self.refill()

    def _filter(self, type, data):
        if type in self.filters:
            f = self.filters[type]
            return f(data)
        return False

    def _notify(self, type, data):
        if type in self.notifiers:
            f = self.notifiers[type]
            f(data)

    def _link_add(self, ifindex, old_iface, new_iface):
            self.kcache_ifaces[ifindex] = new_iface
            self._notify(RTM_NEWLINK, (ifindex, old_iface, new_iface))

    def _link_del(self, ifindex, old_iface):
            del self.kcache_ifaces[ifindex]
            self._notify(RTM_DELLINK, (ifindex, old_iface))

    def _link(self, nlh, ifi):

        if self._filter(nlh.nlmsg_type, ifi):
            return

        ifindex = ifi.ifi_index
        flags = ifi.ifi_flags

        which_ones = [IFLA_IFNAME, IFLA_ADDRESS, IFLA_MTU, IFLA_MASTER]
        rtas = ifi.unpack_rtas(which_ones)

        ifname = rtas.get(IFLA_IFNAME)
        mac_addr = rtas.get(IFLA_ADDRESS)
        mtu = rtas.get(IFLA_MTU)
        master = rtas.get(IFLA_MASTER)

        if nlh.nlmsg_type == RTM_NEWLINK:
            old = self.kcache_ifaces.get(ifindex)
            new = KCacheIface(ifi, flags, ifname, mac_addr, mtu, master)
            if not (old and old.stale and old == new):
                self._link_add(ifindex, old, new)
            if old:
                old.stale = False
        else:
            old = self.kcache_ifaces.get(ifindex)
            if old:
                self._link_del(ifindex, old)

    def _addr_add(self, ifindex, new_addr):
            self.kcache_addrs.setdefault(ifindex, []).append(new_addr)
            self._notify(RTM_NEWADDR, (ifindex, new_addr))

    def _addr_del(self, ifindex, old_addr):
            self.kcache_addrs[ifindex].remove(old_addr)
            if not self.kcache_addrs[ifindex]:
                del self.kcache_addrs[ifindex]
            self._notify(RTM_DELADDR, (ifindex, old_addr))

    def _addr(self, nlh, ifa):

        if self._filter(nlh.nlmsg_type, ifa):
            return

        ifindex = ifa.ifa_index

        which_ones = [IFA_ADDRESS]
        rtas = ifa.unpack_rtas(which_ones)

        addr = rtas.get(IFA_ADDRESS)

        addrs = self.kcache_addrs.get(ifindex, [])
        if nlh.nlmsg_type == RTM_NEWADDR:
            new = KCacheAddr(ifa, addr)
            if new in addrs:
                i = addrs.index(new)
                addrs[i].stale = False
            else:
                self._addr_add(ifindex, new)
        else:
            old = KCacheAddr(ifa, addr)
            if old in addrs:
                self._addr_del(ifindex, old)

    def _route_add(self, dst, new_path):
        self.kcache_routes.setdefault(dst, []).append(new_path)
        self._notify(RTM_NEWROUTE, (dst, new_path))

    def _route_del(self, dst, old_path):
        self.kcache_routes[dst].remove(old_path)
        if not self.kcache_routes[dst]:
            del self.kcache_routes[dst]
        self._notify(RTM_DELROUTE, (dst, old_path))

    def _route(self, nlh, rtm):

        if self._filter(nlh.nlmsg_type, rtm):
            return

        which_ones = [RTA_DST, RTA_OIF, RTA_PREFSRC, RTA_GATEWAY, RTA_PRIORITY]
        rtas = rtm.unpack_rtas(which_ones)

        dst = rtas.get(RTA_DST)
        oif = rtas.get(RTA_OIF)
        prefsrc = rtas.get(RTA_PREFSRC)
        gateway = rtas.get(RTA_GATEWAY)
        priority = rtas.get(RTA_PRIORITY)

        paths = self.kcache_routes.get(dst, [])
        if nlh.nlmsg_type == RTM_NEWROUTE:
            new = KCachePath(rtm, oif, prefsrc, gateway, priority)
            if new in paths:
                i = paths.index(new)
                paths[i].stale = False
            else:
                self._route_add(dst, new)
        else:
            old = KCachePath(rtm, oif, prefsrc, gateway, priority)
            if old in paths:
                self._route_del(dst, old)

    def _neigh_add(self, ifindex, new_neigh):
            self.kcache_neighs.setdefault(ifindex, []).append(new_neigh)
            self._notify(RTM_NEWNEIGH, (ifindex, new_neigh))

    def _neigh_del(self, ifindex, old_neigh):
            self.kcache_neighs[ifindex].remove(old_neigh)
            if not self.kcache_neighs[ifindex]:
                del self.kcache_neighs[ifindex]
            self._notify(RTM_DELNEIGH, (ifindex, old_neigh))

    def _neigh(self, nlh, ndm):

        if self._filter(nlh.nlmsg_type, ndm):
            return

        ifindex = ndm.ndm_ifindex

        which_ones = [NDA_LLADDR, NDA_MASTER]
        rtas = ndm.unpack_rtas(which_ones)

        lladdr = rtas.get(NDA_LLADDR)
        master = rtas.get(NDA_MASTER)

        neighs = self.kcache_neighs.get(ifindex, [])
        if nlh.nlmsg_type == RTM_NEWNEIGH:
            new = KCacheNeigh(ndm, lladdr, master)
            if new in neighs:
                i = neighs.index(new)
                neighs[i].stale = False
            else:
                self._neigh_add(ifindex, new)
        else:
            old = KCacheNeigh(ndm, lladdr, master)
            if old in neighs:
                self._neigh_del(ifindex, old)

    def _cbs(self):
        cbs = {}
        if RTM_GETLINK in self.types:
            cbs[RTM_NEWLINK] = self._link
            cbs[RTM_DELLINK] = self._link
        if RTM_GETADDR in self.types:
            cbs[RTM_NEWADDR] = self._addr
            cbs[RTM_DELADDR] = self._addr
        if RTM_GETROUTE in self.types:
            cbs[RTM_NEWROUTE] = self._route
            cbs[RTM_DELROUTE] = self._route
        if RTM_GETNEIGH in self.types:
            cbs[RTM_NEWNEIGH] = self._neigh
            cbs[RTM_DELNEIGH] = self._neigh
        return cbs

    def _mark_stale(self):

        for ifindex, iface in self.kcache_ifaces.items():
            iface.stale = True

        for ifindex, addrs in self.kcache_addrs.items():
            for addr in addrs:
                addr.stale = True

        for dst, paths in self.kcache_routes.items():
            for path in paths:
                path.stale = True

    def _clean_stale(self):

        stales = [(ifindex, iface) for ifindex, iface in \
            self.kcache_ifaces.items() if iface.stale]
        for ifindex, iface in stales:
            self._link_del(ifindex, iface)

        for ifindex, addrs in self.kcache_addrs.items():
            stales = [addr for addr in addrs if addr.stale]
            for addr in stales:
                self._addr_del(ifindex, addr)

        for dst, paths in self.kcache_routes.items():
            stales = [path for path in paths if path.stale]
            for path in stales:
                self._route_del(dst, path)

    def _request_dump(self):

        for t in self.types:
            if t in [RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH]:
                rtm = Rtgenmsg(self.cache_family)
                token = self.request(t, NLM_F_REQUEST | NLM_F_DUMP, rtm)
                self.process_wait([token])
            if t in [RTM_GETNEIGH]:
                # send extra request for AF_BRIDGE to get bridge neighs
                rtm = Rtgenmsg(AF_BRIDGE)
                token = self.request(t, NLM_F_REQUEST | NLM_F_DUMP, rtm)
                self.process_wait([token])

    def resync(self):
        self._mark_stale()
        self._request_dump()
        self._clean_stale()

    def refill(self):
        self.kcache_ifaces = {}
        self.kcache_addrs = {}
        self.kcache_routes = {}
        self.kcache_neighs = {}
        self._request_dump()

    def iface_by_name(self, name):
        match = [v for k, v in self.kcache_ifaces.items() if v.ifname == name]
        return match[0] if match else None
