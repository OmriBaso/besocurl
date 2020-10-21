import pycurl
import certifi
import io
import sys
import time
import sys
import ctypes
import ctypes.wintypes
import winreg as winreg
# Python 2.x vs 3.x support
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

# --------------------------------------- PAC Parser ------------------------------------------- # 
#
# proxy.py 
# Taken from the Px project
# https://github.com/genotrance/px/blob/master/px.py

# Print if possible
def pprint(*objs):
    try:
        print(*objs)
    except:
        pass


# Windows version
#  6.1 = Windows 7
#  6.2 = Windows 8
#  6.3 = Windows 8.1
# 10.0 = Windows 10
WIN_VERSION = float(str(sys.getwindowsversion().major) + "." + str(sys.getwindowsversion().minor))


###
# Proxy detection

class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(ctypes.Structure):
    _fields_ = [("fAutoDetect", ctypes.wintypes.BOOL), # "Automatically detect settings"
                ("lpszAutoConfigUrl", ctypes.wintypes.LPWSTR), # "Use automatic configuration script, Address"
                ("lpszProxy", ctypes.wintypes.LPWSTR), # "1.2.3.4:5" if "Use the same proxy server for all protocols",
                                                       # else advanced "ftp=1.2.3.4:5;http=1.2.3.4:5;https=1.2.3.4:5;socks=1.2.3.4:5"
                ("lpszProxyBypass", ctypes.wintypes.LPWSTR), # ";"-separated list, "Bypass proxy server for local addresses" adds "<local>"
               ]

class WINHTTP_AUTOPROXY_OPTIONS(ctypes.Structure):
    _fields_ = [("dwFlags", ctypes.wintypes.DWORD),
                ("dwAutoDetectFlags", ctypes.wintypes.DWORD),
                ("lpszAutoConfigUrl", ctypes.wintypes.LPCWSTR),
                ("lpvReserved", ctypes.c_void_p),
                ("dwReserved", ctypes.wintypes.DWORD),
                ("fAutoLogonIfChallenged", ctypes.wintypes.BOOL), ]

class WINHTTP_PROXY_INFO(ctypes.Structure):
    _fields_ = [("dwAccessType", ctypes.wintypes.DWORD),
                ("lpszProxy", ctypes.wintypes.LPCWSTR),
                ("lpszProxyBypass", ctypes.wintypes.LPCWSTR), ]

# Parameters for WinHttpOpen, http://msdn.microsoft.com/en-us/library/aa384098(VS.85).aspx
WINHTTP_NO_PROXY_NAME = 0
WINHTTP_NO_PROXY_BYPASS = 0
WINHTTP_FLAG_ASYNC = 0x10000000

# dwFlags values
WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002

# dwAutoDetectFlags values
WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002

# dwAccessType values
WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
WINHTTP_ACCESS_TYPE_NO_PROXY = 1
WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4

# Error messages
WINHTTP_ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT = 12167

def winhttp_find_proxy_for_url(url, autodetect=False, pac_url=None, autologon=True):
    # Fix issue #51
    ACCESS_TYPE = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
    if WIN_VERSION < 6.3:
        ACCESS_TYPE = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY

    ctypes.windll.winhttp.WinHttpOpen.restype = ctypes.c_void_p
    hInternet = ctypes.windll.winhttp.WinHttpOpen(
        ctypes.wintypes.LPCWSTR("Px"),
        ACCESS_TYPE, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC)
    if not hInternet:
        return ""

    autoproxy_options = WINHTTP_AUTOPROXY_OPTIONS()
    if pac_url:
        autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
        autoproxy_options.dwAutoDetectFlags = 0
        autoproxy_options.lpszAutoConfigUrl = pac_url
    elif autodetect:
        autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
        autoproxy_options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
        autoproxy_options.lpszAutoConfigUrl = 0
    else:
        return ""
    autoproxy_options.fAutoLogonIfChallenged = autologon

    proxy_info = WINHTTP_PROXY_INFO()

    # Fix issue #43
    ctypes.windll.winhttp.WinHttpGetProxyForUrl.argtypes = [ctypes.c_void_p,
        ctypes.wintypes.LPCWSTR, ctypes.POINTER(WINHTTP_AUTOPROXY_OPTIONS),
        ctypes.POINTER(WINHTTP_PROXY_INFO)]
    ok = ctypes.windll.winhttp.WinHttpGetProxyForUrl(hInternet, ctypes.wintypes.LPCWSTR(url),
            ctypes.byref(autoproxy_options), ctypes.byref(proxy_info))
    if not ok:
        error = ctypes.GetLastError()
        if error == WINHTTP_ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT:
            return "DIRECT"
        return ""

    if proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY:
        # Note: proxy_info.lpszProxyBypass makes no sense here!
        if not proxy_info.lpszProxy:
            return ""
        return proxy_info.lpszProxy.replace(" ", ",").replace(";", ",").replace(",DIRECT", "") # Note: We only see the first!
    if proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY:
        return "DIRECT"

    # WinHttpCloseHandle()
    return ""


def parse_proxy(proxystrs):
    if not proxystrs:
        return []

    servers = []
    for proxystr in [i.strip() for i in proxystrs.split(",")]:
        pserver = [i.strip() for i in proxystr.split(":")]
        if len(pserver) == 1 and pserver != 'DIRECT':
            pserver.append(80)
        elif len(pserver) == 2:
            try:
                pserver[1] = int(pserver[1])
            except ValueError:
                pprint("Bad proxy server port: " + pserver[1])
                sys.exit()
        else:
            pprint("Bad proxy server definition: " + proxystr)
            sys.exit()

        if tuple(pserver) not in servers:
            servers.append(tuple(pserver))

    return servers


def how_to_go(url):
    proxies = []
    ieConfig = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
    result = ctypes.windll.winhttp.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(ieConfig))
    if ieConfig.lpszAutoConfigUrl != None:
        pac_url = ieConfig.lpszAutoConfigUrl
        t = winhttp_find_proxy_for_url(url, pac_url=pac_url)
        t = t.split(",")
        if t[0] == 'DIRECT':
            return []
        else:
            for proxy in t:
                proxy = proxy.split(":")
                proxyip, proxyport = proxy[0], proxy[1]
                t = proxyip, int(proxyport)
                proxies.append(t)

            return proxies

    elif ieConfig.lpszProxy != None:
        manual_proxy = ieConfig.lpszProxy
        proxyip, proxyport = manual_proxy.split(":")
        manual_proxy = (proxyip, int(proxyport))
        proxies.append(manual_proxy)

        return proxies
    else:
        return proxies

"""
ieConfig = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
result = ctypes.windll.winhttp.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(ieConfig))
print ("[+] Got IE configuration")
print ("\tAutoDetect: %s" % ieConfig.fAutoDetect)
print ("\tAuto URL: %s" % ieConfig.lpszAutoConfigUrl)
print ("\tProxy: %s" % ieConfig.lpszProxy)
print ("\tProxy Bypass: %s" % ieConfig.lpszProxyBypass)
"""

#==================================================================== CURL Init

def initPyCURL(proxy_servers):
    c = pycurl.Curl()

    if len(proxy_servers) > 0: # Only set proxy if a list was sent - otherwise just initliize curl 
        c.setopt(c.PROXY, proxy_servers[0][0])
        c.setopt(c.PROXYPORT, proxy_servers[0][1])
        c.setopt(c.PROXYAUTH, c.HTTPAUTH_ANY) # To make sure we go through
        # http://curl.haxx.se/mail/tracker-2010-10/0019.html
        #c.setopt(c.PROXYAUTH, c.HTTPAUTH_NTLM)
        c.setopt(c.PROXYUSERPWD, ":")
        
        c.setopt(c.HTTPPROXYTUNNEL, True) # tunnel to get to secure site.

    #c.setopt(c.FOLLOWLOCATION, True) # Follow Redirection - you can change to false, I made it so its enabled automaticly here // Edited to be enabled through method
    CURLOPT_ENCODING = getattr(c, 'ACCEPT_ENCODING', c.ENCODING)
    c.setopt(CURLOPT_ENCODING, '')
    c.setopt(c.FAILONERROR, True)
    c.setopt(c.COOKIEFILE, '')

    c.setopt(c.CAINFO, certifi.where())
    c.setopt(c.SSL_VERIFYPEER, 0)
    c.setopt(c.SSL_VERIFYHOST, 0)

    """
    def log(debug_type, debug_msg):
        print("[%d] %s" % (debug_type, debug_msg.decode('utf-8', 'backslashreplace').strip()))
    c.setopt(c.VERBOSE, True) # set to true if you want debugging
    c.setopt(c.DEBUGFUNCTION, log)
    """
    return c
#==================================================================== CURL Init

def get(url, headers=[], proxies=[], user_agent="Omri-Baso-HumanCurl-Ver.01", allow_redirect=False, auto_detect_proxy=False):
    pycurl.global_init(pycurl.GLOBAL_WIN32)
    pycurl.global_init(pycurl.GLOBAL_SSL)
    buffer = io.BytesIO()
    if auto_detect_proxy == True:
        proxies = how_to_go(url)

    c = initPyCURL(proxies)
    if allow_redirect == False:
        c.setopt(c.FOLLOWLOCATION, False)
    elif allow_redirect == True:
        c.setopt(c.FOLLOWLOCATION, True)
    else:
        raise ValueError('allow_redirect must be true or false')
    if user_agent:
        c.setopt(c.USERAGENT, user_agent)
    if headers:
        c.setopt(pycurl.HTTPHEADER,headers)

    c.setopt(c.URL, url) 
    c.setopt(c.WRITEDATA, buffer)
    c.perform() 
    status_code = c.getinfo(c.RESPONSE_CODE)
    c.close()
    body = buffer.getvalue()
    
    return {'text' : body.decode('utf-8', 'ignore'), 'status_code': int(status_code)}

def post(url, data=None ,headers=[], proxies=[], user_agent="Omri-Baso-HumanCurl-Ver.01", allow_redirect=False , auto_detect_proxy=False):
    pycurl.global_init(pycurl.GLOBAL_WIN32)
    pycurl.global_init(pycurl.GLOBAL_SSL)
    buffer = io.BytesIO()
    if auto_detect_proxy == True:
        proxies = how_to_go(url)

    c = initPyCURL(proxies)
    if allow_redirect == False:
        c.setopt(c.FOLLOWLOCATION, False)
    elif allow_redirect == True:
        c.setopt(c.FOLLOWLOCATION, True)
    else:
        raise ValueError("allow_redirect must be true or false")
    if user_agent:
        c.setopt(c.USERAGENT, user_agent)
    if headers:
        c.setopt(pycurl.HTTPHEADER,headers)

    c.setopt(c.URL, url) 
    c.setopt(c.WRITEDATA, buffer)
    c.setopt(c.POSTFIELDS, data)
    c.perform()
    status_code = c.getinfo(c.RESPONSE_CODE) 
    c.close()
    body = buffer.getvalue()

    return {'text' : body.decode('utf-8', 'ignore'), 'status_code': int(status_code)}

