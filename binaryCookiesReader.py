
#**********************************************************************#
#BinaryCookieReader: Written By Satishb3 (http://www.securitylearn.net)#
#rewrite by Alex 2014-10-23                                            #
#**********************************************************************#

__author__ = 'Alex'

import sys
from struct import unpack
from StringIO import StringIO
from time import strftime, gmtime

if len(sys.argv) != 2:
    sys.exit(0)
FilePath = sys.argv[1]

#FilePath = "/Users/Alex/Desktop/BackupNew/var/mobile/Library/Cookies/Cookies.binarycookies"
try:
    binary_file = open(FilePath, 'rb')
except IOError as e:
    print("open file error")
    sys.exit(0)

file_header = binary_file.read(4)
if str(file_header) != "cook":
    print("not a binaryCookies file")
    sys.exit(0)

num_pages = unpack('>i', binary_file.read(4))[0]

page_sizes = []
for np in range(num_pages):
    page_sizes.append(unpack('>i', binary_file.read(4))[0])
#print(page_sizes)

pages = []
for ps in page_sizes:
    pages.append(binary_file.read(ps))

for page in pages:
    page = StringIO(page)
    page.read(4)
    num_cookies = unpack('<i', page.read(4))[0]

    cookie_offSets = []
    for nc in range(num_cookies):
        cookie_offSets.append(unpack('<i', page.read(4))[0])
    page.read(4)

    cookie = ''
    for offset in cookie_offSets:
        page.seek(offset)
        cookieSize = unpack('<i', page.read(4))[0]
        cookie = StringIO(page.read(cookieSize))

        cookie.read(4)

        flags = unpack('<i', cookie.read(4))[0]
        cookie_flags = ''
        if flags == 0:
            cookie_flags = ''
        elif flags == 1:
            cookie_flags == "Secure"
        elif flags == 4:
            cookie_flags = "HttpOnly"
        elif flags == 5:
            cookie_flags = 'Secure; HttpOnly'
        else:
            cookie_flags = "Unknown"

        cookie.read(4)
        urloffset = unpack('<i', cookie.read(4))[0]
        nameoffset = unpack('<i', cookie.read(4))[0]
        pathoffset = unpack('<i', cookie.read(4))[0]
        valueoffset = unpack('<i', cookie.read(4))[0]

        endofcookie = cookie.read(8)
        expiry_date_epoch = unpack('<d', cookie.read(8))[0]+978307200
        expiry_date = strftime("%a, %d %b %Y ", gmtime(expiry_date_epoch))[:-1]

        create_date_epoch = unpack('<d', cookie.read(8))[0]+978307200
        create_date = strftime("%a, %d %b %Y ", gmtime(create_date_epoch))[:-1]

        cookie.seek(urloffset-4)
        url = ''
        u = cookie.read(1)
        while unpack('<b', u)[0] != 0:
            url += str(u)
            u = cookie.read(1)

        cookie.seek(nameoffset-4)
        name = ''
        n = cookie.read(1)
        while unpack('<b', n)[0] != 0:
            name += str(n)
            n = cookie.read(1)

        cookie.seek(pathoffset-4)
        path = ''
        pa = cookie.read(1)
        while unpack('<b', pa)[0] != 0:
            path += str(pa)
            pa = cookie.read(1)

        cookie.seek(valueoffset-4)
        value = ''
        va = cookie.read(1)
        while unpack('<b',va)[0] != 0:
            value += str(va)
            va = cookie.read(1)
        
        print url

# print 'Cookie : '+name+'='+value+'; domain='+url+'; path='+path+'; '+'expires='+expiry_date+'; '+cookie_flags

binary_file.close()