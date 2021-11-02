import subprocess
import re
import dateutil.parser
from datetime import datetime
from adv_agentx import SnmpGauge32, SnmpCounter32, SnmpIpAddress


class BirdAgent(object):
    _re_birdcli_bgp_peer = {
        "bgpPeerAdminStatus": re.compile("^[a-zA-Z0-9_]+\s+BGP\s+[a-zA-Z0-9-_]+\s+([a-zA-Z0-9]+)\s+\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.*$", re.MULTILINE),
        "bgpPeerState": re.compile("^\s+BGP state:\s+([a-zA-Z]+)$", re.MULTILINE),
        "bgpPeerIdentifier": re.compile("^\s+Neighbor ID:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", re.MULTILINE),
        "bgpPeerLocalAddr": re.compile("^\s+Source address:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", re.MULTILINE),
        "bgpPeerRemoteAddr": re.compile("^\s+Neighbor address:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", re.MULTILINE),
        "bgpPeerRemoteAs": re.compile("^\s+Neighbor AS:\s+([0-9]+)$", re.MULTILINE),
        "bgpPeerLocalAs": re.compile("^\s+Local AS:\s+([0-9]+)$", re.MULTILINE),
        "bgpPeerInUpdates": re.compile("^\s+Import updates:\s+([0-9]+)\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+$", re.MULTILINE),
        "bgpPeerOutUpdates": re.compile("^\s+Export updates:\s+([0-9]+)\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+$", re.MULTILINE),
        "bgpPeerHoldTime": re.compile("^\s+Hold timer:\s+([0-9]+)\/[0-9]+$", re.MULTILINE),
        "bgpPeerHoldTimeConfigured": re.compile("^\s+Hold timer:\s+[0-9]+\/([0-9]+)$", re.MULTILINE),
        "bgpPeerKeepAlive": re.compile("^\s+Keepalive timer:\s+([0-9]+)\/[0-9]+$", re.MULTILINE),
        "bgpPeerKeepAliveConfigured": re.compile("^\s+Keepalive timer:\s+[0-9]+\/([0-9]+)$", re.MULTILINE),
        "bgpPeerLastError": re.compile("^\s+Last error:\s+([a-zA-Z0-9-_\ ]+)$", re.MULTILINE),
        "bgpPeerFsmEstablishedTime": re.compile("^([a-zA-Z0-9_]+)\s+BGP\s+[a-zA-Z0-9-_]+\s+[a-zA-Z0-9]+\s+(\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d).*$", re.MULTILINE),
    }

    _re_ss = re.compile(
        "^[0-9]+\s+[0-9]+\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:%[a-z0-9-\.]+)?:([0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:%[a-z0-9-\.]+?)?:([0-9]+)")

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
        'bgpPeerLocalPort': 0,
        'bgpPeerRemoteAs': 0,
        'bgpPeerRemotePort': 0,
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

    bgp_states = {
        "idle": 1,
        "connect": 2,
        "active": 3,
        "opensent": 4,
        "openconfirm": 5,
        "established": 6,
    }

    def __init__(self, cfgfile, birdcli, sscmd):
        self.cfgfile = cfgfile
        self.birdcli = birdcli
        self.sscmd = sscmd

    @staticmethod
    def bgpKeys():
        return BirdAgent.bgp_keys

    def ipCompare(ip1, ip2):
        lst1 = "%3s.%3s.%3s.%3s" % tuple(ip1.split("."))
        lst2 = "%3s.%3s.%3s.%3s" % tuple(ip2.split("."))
        return (lst1 > lst2)-(lst1 < lst2)

    def getBGPState(self):
        birdc = subprocess.Popen([self.birdcli, "show", "protocols"],
                                 stdout=subprocess.PIPE)
        output = birdc.communicate()[0].decode('utf-8', 'ignore')
        if birdc.returncode != 0:
            print(
                "ERROR: bird-CLI %s failed: %i" %
                (self.birdcli, birdc.returncode))

        protocols = []
        for line in output.split("\n"):
            if line == '':
                continue
            proto = line.split()[0]
            if proto not in ["Name", "BIRD"]:
                protocols.append(proto)

        state = {}
        state["bgp-peers"] = {}
        for proto in protocols:
            state["bgp-peers"][proto] = {}
            birdc = subprocess.Popen([self.birdcli, "show", "protocols", "all", proto],
                                     stdout=subprocess.PIPE)
            output = birdc.communicate()[0].decode('utf-8', 'ignore')
            if birdc.returncode != 0:
                print(
                    "ERROR: bird-CLI %s failed: %i" %
                    (self.birdcli, birdc.returncode))
            try:
                for peerprop_name, peerprop_re in list(
                        self._re_birdcli_bgp_peer.items()):
                    match = peerprop_re.search(output)
                    if peerprop_name == 'bgpPeerAdminStatus' and match:
                        if match.group(1) == 'down':
                            state["bgp-peers"][proto][peerprop_name] = int(
                                1)
                            state["bgp-peers"][proto]["bgpPeerAdminStatus"] = int(
                                1)
                            state["bgp-peers"][proto]["bgpPeerFsmEstablishedTime"] = int(
                                0)
                    elif peerprop_name == 'bgpPeerState' and not match and 'bgpPeerAdminStatus' not in state["bgp-peers"][proto]:
                        del state["bgp-peers"][proto]
                        break
                    elif peerprop_name == 'bgpPeerFsmEstablishedTime' and match:
                        timestamp = dateutil.parser.parse(match.group(2))
                        current_time = datetime.now()
                        state["bgp-peers"][proto]["bgpPeerFsmEstablishedTime"] = SnmpGauge32(
                            abs(current_time - timestamp).total_seconds())
                    elif match:
                        if peerprop_name == 'bgpPeerState':
                            if not match.group(1).lower() == 'down':
                                state["bgp-peers"][proto][peerprop_name] = \
                                    self.bgp_states[match.group(1).lower()]
                            else:
                                # handle disabled (down) protocols
                                state["bgp-peers"][proto][peerprop_name] = int(
                                    1)
                                state["bgp-peers"][proto]["bgpPeerAdminStatus"] = int(
                                    1)
                                state["bgp-peers"][proto]["bgpPeerFsmEstablishedTime"] = int(
                                    0)

                        elif peerprop_name in [
                            'bgpPeerIdentifier',
                                'bgpPeerLocalAddr',
                                'bgpPeerRemoteAddr']:
                            state["bgp-peers"][proto][peerprop_name] = SnmpIpAddress(
                                match.group(1))
                        elif peerprop_name in [
                            'bgpPeerInUpdates',
                                'bgpPeerOutUpdates']:
                            state["bgp-peers"][proto][peerprop_name] = SnmpCounter32(
                                match.group(1))
                        else:
                            state["bgp-peers"][proto][peerprop_name] = int(
                                match.group(1))
            except:
                print("WARNING: Unable to process \"%s\" as \"%s\" for protocol \"%s\"" %
                      (match.group(1), peerprop_name, proto))

        local_as = set(peer["bgpPeerLocalAs"]
                       for peer in state["bgp-peers"].values())
        try:
            state["bgpLocalAs"] = min(local_as)
            if len(local_as) > 1:
                print("WARNING: multiple local AS: %s; using %i" % (
                    ", ".join(str(asn) for asn in local_as), state["bgpLocalAs"]))
        except ValueError:
            print("ERROR: No local AS found, terminating...")

        bgp_sessions = {}
        try:
            ss = subprocess.Popen(self.sscmd, shell=True,
                                  stdout=subprocess.PIPE)

            for line in ss.communicate()[0].decode('utf-8', 'ignore').split("\n"):
                match = self._re_ss.search(line)
                if not match:
                    continue
                # key 4-tuples by remote ip: src-addr, src-port, dst-addr, dst-port
                bgp_sessions[match.group(3)] = match.groups()
        except subprocess.CalledProcessError as e:
            print(
                "ERROR: Error executing \"ss\" command [%s], terminating..." % e)

         # match the connection 4-tuples with bgp-state
        for proto in list(state["bgp-peers"].keys()):
            if not state["bgp-peers"][proto]:
                continue

            # enrich the state by local+remote ports
            try:
                srcip, srcport, dstip, dstport = bgp_sessions[state["bgp-peers"][
                    proto]["bgpPeerRemoteAddr"]]
            except:
                print("INFO: Protocol \"%s\" has no active BGP session." % proto)
                state["bgp-peers"][proto]["bgpPeerRemoteAddr"] = SnmpIpAddress(
                    "0.0.0.0")

            # populate the ports
            state["bgp-peers"][proto]["bgpPeerLocalPort"] = int(srcport)
            state["bgp-peers"][proto]["bgpPeerRemotePort"] = int(dstport)

        return state