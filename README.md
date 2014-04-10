heartbleedchecker
=================

- Checks SSL 3, TLS 1.0,1.1.,1.2

Iterate through an input file that is a list of hostnames or IPs, 
and output whether or not they are vulnerable in a greppable format.

Script uses 443 by default, you can override for all targets, and
you can specify per-line custom ports (mix n' match is OK).

Usage: **./ssltest.py *inputfile* *[port]***

Sample inputfile:
```
www.domain1.com
domain2.net
8.8.8.8
customport.domain3.org:8443
```

