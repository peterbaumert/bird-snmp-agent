#
# Copyright (c) 2016 Travelping GmbH <copyright@travelping.com>
# by Tobias Hintze <tobias.hintze@travelping.com>
#
# This code is inspired and partially copied from
# https://r3blog.nl/index.php/archives/2011/02/24/bgp4-mib-support-for-bird/
# That original code does not clearly declare any license.
#
# This code also uses python-agentx library licensed under GPLv3
# (see agentx.py for details)
#
# So this code is licensed under the GPLv3 (see COPYING.GPLv3).
#

"""
birdagent - agentx code for the bird routing daemon
	used by bird_bgp - for the bgp4-mib
"""
from __future__ import print_function

from past.builtins import cmp
from builtins import object
from adv_agentx import AgentX
from adv_agentx import SnmpGauge32, SnmpCounter32, SnmpIpAddress
import re
import subprocess
import glob
import dateutil.parser
from datetime import datetime
import pytz
from tzlocal import get_localzone


class BirdAgent(object):

    def __init__(self, cfgfile, birdcli, sscmd):
        self.cfgfile = cfgfile
        self.birdcli = birdcli
        self.sscmd = sscmd

    bgp_states = {
        "idle": 1,
        "connect": 2,
        "active": 3,
        "opensent": 4,
        "openconfirm": 5,
        "established": 6,
    }

    _re_config_include = re.compile("^include\s*\"(/[^\"]*)\".*$")
    _re_config_bgp_proto_begin = re.compile(
        "^protocol bgp ([a-zA-Z0-9_]+).*\{$")
    _re_config_local_as = re.compile(
        "local ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) as ([0-9]+);")
    _re_config_bgp_holdtime = re.compile("hold time ([0-9]+);")
    _re_config_bgp_keepalive = re.compile("keepalive time ([0-9]+);")
    _re_config_remote_peer = re.compile(
        "neighbor ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) as ([0-9]+);")
    _re_config_timeformat = re.compile(
        "\s*timeformat\s+protocol\s+iso\s+long\s+;")
    _re_config_proto_end = re.compile("^\}$")

    _re_birdcli_bgp_begin = re.compile(
        "([a-zA-Z0-9_]+) *BGP * [a-zA-Z0-9_]+ * [a-zA-Z0-9]+ * (\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d) *")
    _re_birdcli_bgp_peer = {
        "bgpPeerIdentifier": re.compile("Neighbor ID:.* ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"),
        "bgpPeerState": re.compile("BGP state:.* ([a-zA-Z]+)"),
        "bgpPeerLocalAddr": re.compile("Source address:.* ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"),
        "bgpPeerRemoteAddr": re.compile("Neighbor address:.* ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"),
        "bgpPeerRemoteAs": re.compile("Neighbor AS:.* ([0-9]+)"),
        "bgpPeerInUpdates": re.compile("Import updates:\ +([0-9]+) .*[0-9\-]+.*[0-9\-]+.*[0-9\-]+.*[0-9\-]+"),
        "bgpPeerOutUpdates": re.compile("Export updates:\ +([0-9]+) .*[0-9\-]+.*[0-9\-]+.*[0-9\-]+.*[0-9\-]+"),
        "bgpPeerHoldTime": re.compile("Hold timer:.* ([0-9]+)/[0-9]+"),
        "bgpPeerHoldTimeConfigured": re.compile("Hold timer:.* [0-9]+/([0-9]+)"),
        "bgpPeerKeepAlive": re.compile("Keepalive timer:.* ([0-9]+)/[0-9]+"),
        "bgpPeerKeepAliveConfigured": re.compile("Keepalive timer:.* [0-9]+/([0-9]+)"),
        "bgpPeerLastError": re.compile("Last error:\ +[a-zA-Z0-9-_\ ]+$")}
    _re_birdcli_bgp_end = re.compile("^$")

    _re_ss = re.compile(
        "^[0-9]+\s+[0-9]+\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:%[a-z0-9-]+)?:([0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:%[a-z0-9-]+?)?:([0-9]+)")

    bgp_keys = [
        'bgpPeerIdentifier',
        'bgpPeerState',
        'bgpPeerAdminStatus',
        'bgpPeerNegotiatedVersion',
        'bgpPeerLocalAddr',
        'bgpPeerLocalPort',
        'bgpPeerRemoteAddr',
        'bgpPeerRemotePort',
        'bgpPeerRemoteAs',
        'bgpPeerInUpdates',
        'bgpPeerOutUpdates',
        'bgpPeerInTotalMessages',
        'bgpPeerOutTotalMessages',
        'bgpPeerLastError',
        'bgpPeerFsmEstablishedTransitions',
        'bgpPeerFsmEstablishedTime',
        'bgpPeerConnectRetryInterval',
        'bgpPeerHoldTime',
        'bgpPeerKeepAlive',
        'bgpPeerHoldTimeConfigured',
        'bgpPeerKeepAliveConfigured',
        'bgpPeerMinASOriginationInterval',
        'bgpPeerMinRouteAdvertisementInterval',
        'bgpPeerInUpdateElapsedTime',
    ]

    bgp_defaults = {
        'bgpPeerIdentifier': SnmpIpAddress("0.0.0.0"),
        'bgpPeerLocalAddr': SnmpIpAddress("0.0.0.0"),
        'bgpPeerHoldTime': 0,
        'bgpPeerHoldTimeConfigured': 0,
        'bgpPeerKeepAlive': 0,
        'bgpPeerKeepAliveConfigured': 0,
        'bgpPeerState': 1,
        'bgpPeerInUpdates': SnmpCounter32(0),
        'bgpPeerOutUpdates': SnmpCounter32(0),
        'bgpPeerAdminStatus': 2,
        'bgpPeerConnectRetryInterval': 0,
        'bgpPeerFsmEstablishedTime': SnmpGauge32(0),
        'bgpPeerFsmEstablishedTransitions': SnmpCounter32(0),
        'bgpPeerInTotalMessages': SnmpCounter32(0),
        'bgpPeerInUpdateElapsedTime': SnmpGauge32(0),
        'bgpPeerLastError': '0',
        'bgpPeerMinASOriginationInterval': 15,
        'bgpPeerMinRouteAdvertisementInterval': 30,
        'bgpPeerNegotiatedVersion': 0,
        'bgpPeerOutTotalMessages': SnmpCounter32(0),
    }

    @staticmethod
    def ipCompare(ip1, ip2):
        lst1 = "%3s.%3s.%3s.%3s" % tuple(ip1.split("."))
        lst2 = "%3s.%3s.%3s.%3s" % tuple(ip2.split("."))
        return cmp(lst1, lst2)

    @staticmethod
    def combinedConfigLines(filename):
        """
        yield the whole bird configuration file line by line;
        all include-statements are resolved/unrolled
        """
        with open(filename, "r") as bird_conf:
            for line in bird_conf:
                line = line.strip()
                match = BirdAgent._re_config_include.search(line)
                if not match:
                    yield line
                else:
                    for subconf in glob.glob(match.group(1)):
                        yield "# subconf: %s (from %s)" % (subconf, line)
                        for subline in BirdAgent.combinedConfigLines(subconf):
                            yield subline

    @staticmethod
    def bgpKeys():
        return BirdAgent.bgp_keys

    def getBGPState(self):
        """
        fetch BGP-related state from:
        * parsing configuration file
        * parsing `birdc show protocols all` output
        * parsing `ss` output
        """

        timezone = get_localzone()
        current_time = datetime.now(pytz.utc)

        # fetch some data from the configuration:
        cfg = {}
        cfg["bgp-peers"] = {}
        proto = None
        for line in BirdAgent.combinedConfigLines(self.cfgfile):
            if self._re_config_timeformat:
                cfg["timeformat"] = True
            match = self._re_config_bgp_proto_begin.search(line)
            if match:
                proto = match.group(1)
                cfg["bgp-peers"][proto] = {}
            if proto:
                match = self._re_config_local_as.search(line)
                if match:
                    cfg["bgp-peers"][proto]["bgpPeerLocalAddr"] = SnmpIpAddress(
                        match.group(1))
                    cfg["bgp-peers"][proto]["bgpPeerLocalAs"] = int(
                        match.group(2))
                    if "bgpLocalAs" not in cfg:
                        cfg["bgpLocalAs"] = int(match.group(2))
                    elif cfg["bgpLocalAs"] != int(match.group(2)):
                        print("WARNING: multiple local AS: %i/%i" %
                              (cfg["bgpLocalAs"], int(match.group(2))))
                match = self._re_config_remote_peer.search(line)
                if match:
                    cfg["bgp-peers"][proto]["bgpPeerRemoteAddr"] = SnmpIpAddress(
                        match.group(1))
                    cfg["bgp-peers"][proto]["bgpPeerRemoteAs"] = int(
                        match.group(2))

                match = self._re_config_bgp_holdtime.search(line)
                if match:
                    cfg["bgp-peers"][proto]["bgpPeerHoldTimeConfigured"] = int(
                        match.group(1))

                match = self._re_config_bgp_keepalive.search(line)
                if match:
                    cfg["bgp-peers"][proto]["bgpPeerKeepAliveConfigured"] = int(
                        match.group(1))

            if self._re_config_proto_end.search(line):
                proto = None
        if "timeformat" not in cfg:
            print("WARNING: timeformat not configured for this agent's use.")

        state = cfg.copy()
        bgp_proto = None
        # "with"-context-manager for Popen not available in python < 3.2
        birdc = subprocess.Popen([self.birdcli, "show", "protocols", "all"],
                                 stdout=subprocess.PIPE)
        output = birdc.communicate()[0].decode('utf-8', 'ignore')
        if birdc.returncode != 0:
            print(
                "ERROR: bird-CLI %s failed: %i" %
                (self.birdcli, birdc.returncode))
        for line in output.split("\n"):
            match = self._re_birdcli_bgp_begin.search(line)
            if match:
                bgp_proto = match.group(1)
                timestamp = dateutil.parser.parse(match.group(2))
                if not timestamp.tzinfo:
                    timestamp = timezone.localize(timestamp)
                if bgp_proto not in state["bgp-peers"]:
                    print(
                        "WARNING: proto \"%s\" not in config, skipping" %
                        bgp_proto)
                    continue
                state["bgp-peers"][bgp_proto]["bgpPeerFsmEstablishedTime"] = SnmpGauge32(
                    abs(current_time - timestamp).total_seconds())
            if bgp_proto:
                for peerprop_name, peerprop_re in list(
                        self._re_birdcli_bgp_peer.items()):
                    match = peerprop_re.search(line)
                    if match:
                        if peerprop_name == 'bgpPeerState':
                            state["bgp-peers"][bgp_proto][peerprop_name] = \
                                self.bgp_states[match.group(1).lower()]
                        elif peerprop_name in [
                            'bgpPeerIdentifier',
                            'bgpPeerLocalAddr',
                                'bgpPeerRemoteAddr']:
                            state["bgp-peers"][bgp_proto][peerprop_name] = SnmpIpAddress(
                                match.group(1))
                        elif peerprop_name in [
                            'bgpPeerInUpdates',
                                'bgpPeerOutUpdates']:
                            state["bgp-peers"][bgp_proto][peerprop_name] = SnmpCounter32(
                                match.group(1))
                        else:
                            state["bgp-peers"][bgp_proto][peerprop_name] = int(
                                match.group(1))
            if self._re_birdcli_bgp_end.search(line):
                bgp_proto = None

        # use ss to query for tcp:179 connections
        bgp_sessions = {}
        ss = subprocess.Popen(self.sscmd, shell=True, stdout=subprocess.PIPE)
        for line in ss.communicate()[0].decode('utf-8', 'ignore').split("\n"):
            match = self._re_ss.search(line)
            if not match:
                continue
            # key 4-tuples by remote ip: src-addr, src-port, dst-addr, dst-port
            bgp_sessions[match.group(3)] = match.groups()

        # now match the tcp:179 4-tuples with bgp-state,
        # and enrich state by local+remote ports
        for proto in list(state["bgp-peers"].keys()):
            state["bgp-peers"][proto]["bgpPeerLocalPort"] = 0
            state["bgp-peers"][proto]["bgpPeerRemotePort"] = 0
            if state["bgp-peers"][proto]["bgpPeerRemoteAddr"] not in bgp_sessions:
                # print("INFO: proto %s has no bgp session."%proto)
                continue
            srcip, srcport, dstip, dstport = bgp_sessions[state["bgp-peers"][
                proto]["bgpPeerRemoteAddr"]]
            if srcip != state["bgp-peers"][proto]["bgpPeerLocalAddr"] or \
                    dstip != state["bgp-peers"][proto]["bgpPeerRemoteAddr"]:
                print(
                    "WARNING: proto %s has invalid BGP session (%s / %s)" %
                    (proto, srcip, dstip))
                continue
            state["bgp-peers"][proto]["bgpPeerLocalPort"] = int(srcport)
            state["bgp-peers"][proto]["bgpPeerRemotePort"] = int(dstport)

        return state
