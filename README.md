## bird-snmp-agent

Based on https://github.com/carosio/bird-snmp-agent

Forked by Mike Nowak (https://github.com/mikenowak)

Forked by Peter Baumert (https://github.com/peterbaumert)

### What?

* implements an SNMP-AgentX extension for the bird-routing-daemon

### How?

To collect its data this agent:

* uses `birdc` CLI of bird
* calls `ss` to query information about used tcp-ports

## Dependencies

The script depends on the following libraries:
* dateutil

It also expects the `snmp-mibs-downloader` package.

All of these can be installed on Ubuntu as follows:

`apt install snmp-mibs-downloader`
and
`pip install -r requirements.txt`

## Usage

### Enable agentx support in snmp

Add the following line to `snmpd.conf`:

```
master	agentx
agentxperms 0770 0770 root snmp # if you intend to run this as an unprivileged user
```

### Set bird's timestamp to iso8601 long

The script expect the timestamps to be in the iso8601 long format (YYYY-MM-DD HH:MM:SS)

To enable this, add the following to global section of `bird.conf`:

```
timeformat base iso long;
timeformat log iso long;
timeformat protocol iso long;
timeformat route iso long;
```

NB: Only protocol line is needed, the rest are optional, but keep the output from birdc consistent.

## Settings

The script takes the following environment variables:

* BIRDCONF           path to bird.conf (defaults to '/etc/bird/bird.conf')
* BIRDCLI            name of birdcli exacutable (defaults to '/usr/sbin/birdc')
* SSCMD              ss command syntax (defaults to "ss -tan -o state established '( dport = :bgp or sport = :bgp )'")
* BGPMIBFILE         location of the BGP-MIB4 file (defaults to '/var/lib/mibs/ietf/BGP4-MIB')
* AGENTCACHEINTERVAL how long to keep results cached in seconds (defaults to '30')


## SystemD Unit File

```
[Unit]
Description=BIRD SNMP Agent
After=snmp.service
[Service]
PermissionsStartOnly = true
User = snmp
Group = snmp
WorkingDirectory = /usr/local/bird-snmp-agent
ExecStart = /usr/bin/env python3 /usr/local/bird-snmp-agent/bird_bgp.py
ExecReload = /bin/kill -s HUP $MAINPID
ExecStop = /bin/kill -s TERM $MAINPID
PrivateTmp = true

[Install]
WantedBy=multi-user.target
```

NB1: The `snmp` user needs to be a member of the `bird` group in order to query bird.

NB2: If you decide to run the script as a non-provileged user the following are also needed:

```
chgrp snmp /var/agentx
chmod 0750 /var/agentx
```
