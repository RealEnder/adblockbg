#!/usr/bin/python
# The source code is distributed under GPLv3 license
import sys
import os.path
import string
import urlparse
import socket
import urllib2

print 'Check AdBlockPlus filters for outdated entries v 0.1 by Alex Stanev, http://stanev.org/abp'

if len(sys.argv) == 2:
    if os.path.exists(sys.argv[1]):
        socket.setdefaulttimeout(5)
        no_res = 0
        no_host = 0
        skip = 0
        short = 0
        curr = 0
        
        
        abplist = open(sys.argv[1])
        for line in abplist:
            curr = curr + 1
            rline = line.strip()
            
            #check for comment or empty ot section [
            if len(rline) == 0:
                skip = skip + 1
                continue
            if rline[0] in ('[','!'):
                skip = skip + 1
                continue
            
            #check for short entries
            if len(rline) <= 6:
                short = short + 1
                print curr,': Too short :',line,
                continue
            
            # remove #, $, ~ if present
            if rline.find('#') <> -1:
                rline = rline[0:rline.find('#')]
            if rline.find('$') <> -1:
                rline = rline[0:rline.find('$')]
            if rline.find('~') <> -1:
                rline = rline[0:rline.find('~')]
                
            #check whitelists too
            if rline[0:1] == '@@':
                rline = rline[2:len(rline)-2]
            if rline[1] == '|':
                rline = rline[1:len(rline)-1]
                
            #check for protocol idents
            if rline[0:7].lower() == 'http://' or rline[0:8].lower() == 'https://':
                print curr,': Consider removing protocol identificator :',line,
            else:
                rline='http://'+rline
            
            url = urlparse.urlparse(rline)
            
            #check for wildcards in host
            if url[1] == '' or url[1].find('*') <> -1:
                no_host = no_host + 1
                #print curr,': Wildcard or missing host :',line,
                continue
            
            #remove wildcards in path if present
            path = url[2]
            if len(path) > 1:
                while path.endswith('.'):
                    path = path[0:path.rfind('/')]
                while path.rfind('*') <> -1:
                    path = path[0:path.rfind('*')]
                    path = path[0:path.rfind('/')]
            
            #access the resource
            try:
                resp = urllib2.urlopen(url[0]+'://'+url[1]+path);
            except Exception, e:
                if hasattr(e, 'code'):
                    if e.code == 404:
                        no_res = no_res + 1
                        print curr,': Resource not found :',line,
                        
        abplist.close()
        print '\nChecked lines:%s\nNot found:%s\nIndeterminable:%s\nToo short:%s\nSkipped:%s' %(curr, no_res, no_host, short, skip)
        sys.exit(0)
        
print 'Usage: abp_list_check.py [abp_list.txt]'
sys.exit(1)

