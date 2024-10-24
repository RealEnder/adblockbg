#!/usr/bin/python3
# (c) Alex Stanev <alex@stanev.org>, https://stanev.org/abp
# The source code is distributed under GPLv3 license
import sys
import os.path
import urllib.parse
import socket
from urllib.request import urlopen
from urllib.error import HTTPError, URLError

print('Check AdBlockPlus filters for outdated entries\nver 0.3 (c) Alex Stanev, https://stanev.org/abp\n')

if len(sys.argv) != 2:
    print('Usage: %s [abp_list.txt]' % sys.argv[0])
    sys.exit(0)
if not os.path.exists(sys.argv[1]):
    print('Could not find the list')
    sys.exit(1)

socket.setdefaulttimeout(2)
no_res  = 0
no_conn = 0
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
        print('%i: Too short : %s' % (curr, line), end='')
        continue

    #remove single or double starting pipe
    while rline[0] == '|' or rline[0] == '@':
        rline = rline[1:]
        
    #check for protocol idents
    if rline.startswith(('http://', 'https://')):
        print('%i: Consider removing protocol identificator : %s' % (curr, line), end='')
    else:
        rline = 'http://' + rline
    
    url = urllib.parse.urlparse(rline)

    #check for wildcards in host
    if url[1] == '' or url[1].find('*') != -1:
        no_host += 1
        #print('%i: Wildcard or missing host : %s' % (curr, line), end='')
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
    for domain in url[1].split(','):
        try:
            urlopen(url[0]+'://' + domain + path)
        except HTTPError as e:
            if e.code in (404, 410):
                no_res += 1
                print('%i: %i Resource not found : %s' % (curr, e.code, line), end='')
            if e.code >= 500:
                print('%i: %i Server error : %s' % (curr, e.code, line), end='')
        except URLError as e:
            no_conn += 1
            print('%i: %s : %s : %s' % (curr, e.reason, line.strip(), url[0] + '://' + domain + path.strip()))
        except Exception:
            None
        except KeyboardInterrupt as ex:
            print('Keyboard interrupt')
            break
                
abplist.close()

print('\nChecked lines:%i\nNot found:%i\nConnection error:%i\nIndeterminable:%i\nToo short:%i\nSkipped:%i' % (curr, no_res, no_conn, no_host, short, skip))
