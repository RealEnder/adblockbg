#!/usr/bin/python
# The source code is distributed under GPLv3 license
import sys
import os.path
import urlparse
import socket
from urllib2 import urlopen, HTTPError

print 'Check AdBlockPlus filters for outdated entries v0.2.3 by Alex Stanev, http://stanev.org/abp'

if len(sys.argv) != 2:
    print 'Usage: %s [abp_list.txt]' % sys.argv[0]
    sys.exit(0)
if not os.path.exists(sys.argv[1]):
    print 'Could not find the list'
    sys.exit(1)

socket.setdefaulttimeout(2)
no_res  = 0
no_host = 0
skip    = 0
short   = 0
curr    = 0

abplist = open(sys.argv[1])
for line in abplist:
    curr += 1
    rline = line.strip()

    #remove #, $, ~, ^
    #check for comment or empty or section [
    for sym in ('#', '$', '~', '^', '[', '!'):
        if rline.find(sym) != -1:
            rline = rline[:rline.find(sym)]

    if rline == '':
        skip += 1
        continue
    
    #check for short entries
    if len(rline) < 3:
        short += 1
        print '%i: Too short : %s' % (curr, line),
        continue

    #check whitelists too
    if rline[0:1] == '@@':
        rline = rline[2:]

    #remove single or double starting pipe
    while rline[0] == '|':
        rline = rline[1:]
        
    #check for protocol idents
    if rline.startswith(('http://', 'https://')):
        print '%i: Consider removing protocol identificator : %s' % (curr, line),
    else:
        rline = 'http://' + rline
    
    url = urlparse.urlparse(rline)
    
    #check for wildcards in host
    if url[1] == '' or url[1].find('*') != -1:
        no_host += 1
        #print '%i: Wildcard or missing host : %s' % (curr, line),
        continue
    
    #remove wildcards in path if present
    path = url[2]
    if len(path) > 1:
        while path.endswith('.'):
            path = path[:path.rfind('/')]
        while path.rfind('*') != -1:
            path = path[:path.rfind('*')]
            path = path[:path.rfind('/')]
    
    #access the resource
    #print url[0]+'://'+url[1]+path
    try:
        urlopen(url[0]+'://'+url[1]+path)
    except HTTPError, e:
        if e.code in (404, 410):
            no_res += 1
            print '%i: %i Resource not found : %s' % (curr, e.code, line),
        if e.code >= 500:
            print '%i: %i Server error : %s' % (curr, e.code, line),
    except Exception:
        None
                
abplist.close()
print '\nChecked lines:%i\nNot found:%i\nIndeterminable:%i\nToo short:%i\nSkipped:%i' % (curr, no_res, no_host, short, skip)
