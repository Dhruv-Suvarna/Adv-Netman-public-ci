"""The port names Arista EOS prints in an access-list entry, mapped back to the port number.

EOS stores ``eq 80`` but displays ``eq www``.  This table is not hand-written: it is what cEOS 4.36.2F displayed (in an
aborted configuration session, so nothing was committed) for ``permit tcp|udp any eq N any`` over every port 1-1024 and
the high ports {1080, 1433, 1521, 1645, 1646, 1701, 1723, 1812, 1813, 2049, 3306, 3389, 3784, 3785, 4500, 4789, 5060, 5432,
6633, 6653, 8080, 8443} (captured 2026-10-28).  A name outside the table is never guessed: the caller keeps the entry
unmodelled.
"""

from __future__ import annotations

TCP = {
    "tcpmux": 1, "rje": 5, "echo": 7, "discard": 9, "systat": 11, "daytime": 13, "qotd": 17, "msp": 18, "chargen": 19,
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "nsw-fe": 27, "msg-icp": 29, "dsp": 33, "time": 37,
    "rlp": 39, "whois": 43, "gre": 47, "tacacs": 49, "re-mail-ck": 50, "la-maint": 51, "xns-time": 52, "domain": 53,
    "xns-ch": 54, "isi-gl": 55, "xns-mail": 58, "gopher": 70, "netrjs-1": 71, "netrjs-2": 72, "netrjs-3": 73,
    "netrjs-4": 74, "finger": 79, "www": 80, "kerberos": 88, "hostname": 101, "iso-tsap": 102, "acr-nema": 104,
    "csnet-ns": 105, "rtelnet": 107, "snagas": 108, "pop2": 109, "pop3": 110, "sunrpc": 111, "ident": 113,
    "uucp-path": 117, "sqlserv": 118, "nntp": 119, "imap": 143, "bftp": 152, "sgmp": 153, "sqlsrv": 156, "snmp": 161,
    "snmptrap": 162, "print-srv": 170, "vmnet": 175, "bgp": 179, "irc": 194, "smux": 199, "at-rtmp": 201, "qmtp": 209,
    "z39-50": 210, "ipx": 213, "mpp": 218, "imap3": 220, "esro-gen": 259, "bgmp": 264, "http-mgmt": 280,
    "asip-webadmin": 311, "pkix-timestamp": 318, "ptp-event": 319, "ptp-general": 320, "matip-type-a": 350,
    "matip-type-b": 351, "odmr": 366, "rpc2portmap": 369, "clearcase": 371, "hp-alarm-mgr": 383, "arns": 384,
    "aurp": 387, "ldap": 389, "ups": 401, "svrloc": 427, "https": 443, "snpp": 444, "microsoft-ds": 445,
    "kpasswd": 464, "tcpnethaspsrv": 475, "pim-auto-rp": 496, "citadel": 504, "exec": 512, "login": 513, "cmd": 514,
    "lpd": 515, "talk": 517, "efs": 520, "ncp": 524, "courier": 530, "netwnews": 532, "uucp": 540, "commerce": 542,
    "klogin": 543, "kshell": 544, "dhcpv6-client": 546, "dhcpv6-server": 547, "afpovertcp": 548, "new-rwho": 550,
    "rtsp": 554, "remotefs": 556, "nntps": 563, "submission": 587, "http-alt": 591, "http-rpc-epmap": 593,
    "tunnel": 604, "ipp": 631, "rlzdbase": 635, "ldaps": 636, "msdp": 639, "repcmd": 641, "ldp": 646, "rmc": 657,
    "mac-srvr-admin": 660, "acap": 674, "msexch-routing": 691, "ha-cluster": 694, "ieee-mms-ssl": 695, "epp": 700,
    "lmp": 701, "iris-beep": 702, "silc": 706, "cisco-tdp": 711, "tbrpf": 712, "kerberos-adm": 749, "netconf-ssh": 830,
    "dhcp-failover2": 847, "godi": 848, "iscsi": 860, "rsync": 873, "ftps-data": 989, "ftps": 990, "nas": 991,
    "imaps": 993, "pop3s": 995, "ms-sql-s": 1433, "pptp": 1723, "radius": 1812, "radius-acct": 1813, "nfs": 2049,
}

UDP = {
    "tcpmux": 1, "rje": 5, "echo": 7, "discard": 9, "systat": 11, "daytime": 13, "qotd": 17, "msp": 18, "chargen": 19,
    "nsw-fe": 27, "msg-icp": 29, "dsp": 33, "time": 37, "rlp": 39, "nameserver": 42, "tacacs": 49, "re-mail-ck": 50,
    "la-maint": 51, "xns-time": 52, "domain": 53, "xns-ch": 54, "isi-gl": 55, "xns-mail": 58, "bootps": 67,
    "bootpc": 68, "tftp": 69, "kerberos": 88, "acr-nema": 104, "csnet-ns": 105, "snagas": 108, "sunrpc": 111,
    "auth": 113, "sqlserv": 118, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138, "netbios-ss": 139, "bftp": 152,
    "sgmp": 153, "sqlsrv": 156, "snmp": 161, "snmptrap": 162, "xdmcp": 177, "dnsix": 195, "smux": 199, "at-rtmp": 201,
    "qmtp": 209, "z39-50": 210, "ipx": 213, "mpp": 218, "imap3": 220, "esro-gen": 259, "bgmp": 264, "http-mgmt": 280,
    "pkix-timestamp": 318, "ptp-event": 319, "ptp-general": 320, "matip-type-a": 350, "matip-type-b": 351, "odmr": 366,
    "rpc2portmap": 369, "clearcase": 371, "hp-alarm-mgr": 383, "arns": 384, "aurp": 387, "ldap": 389, "ups": 401,
    "svrloc": 427, "mobile-ip": 434, "snpp": 444, "kpasswd": 464, "tcpnethaspsrv": 475, "pim-auto-rp": 496,
    "isakmp": 500, "citadel": 504, "biff": 512, "who": 513, "syslog": 514, "talk": 517, "rip": 520, "ncp": 524,
    "timed": 525, "courier": 530, "netwall": 533, "commerce": 542, "dhcpv6-client": 546, "dhcpv6-server": 547,
    "new-rwho": 550, "rtsp": 554, "rmonitor": 560, "monitor": 561, "nntps": 563, "http-rpc-epmap": 593,
    "asf-rmcp": 623, "ipp": 631, "rlzdbase": 635, "ldaps": 636, "msdp": 639, "repcmd": 641, "ldp": 646, "rmc": 657,
    "ha-cluster": 694, "olsr": 698, "kerberos-adm": 749, "godi": 848, "ftps-data": 989, "ftps": 990, "nas": 991,
    "l2tp": 1701, "pptp": 1723, "radius": 1812, "radius-acct": 1813, "nfs": 2049, "bfd": 3784, "bfd-echo": 3785,
    "non500-isakmp": 4500,
}


def port_number(protocol: str, token: str) -> int | None:
    """``token`` as EOS displays a port of ``protocol`` -> its number; None for an unknown name or an invalid number."""
    text = str(token or "").strip().lower()
    if text.isdigit():
        number = int(text)
        return number if 0 <= number <= 65535 else None
    table = TCP if str(protocol or "").upper() == "TCP" else UDP if str(protocol or "").upper() == "UDP" else {}
    return table.get(text)
