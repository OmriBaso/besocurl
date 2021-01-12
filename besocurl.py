import os
try:
    import pycurl
except ImportError:
    print("Cannot Import PyCurl , would you like to install it?")   

#$pathvargs = {C:\Temp\UpgradeClientInstaller\setup.exe /S /v/qn }
# Invoke-Command -ScriptBlock $pathvargs     
import certifi
import io
import sys, platform
import ctypes, sys
try:
    import ctypes.wintypes
except ValueError:
    print("[-] %s - Windows Features cannot be used on Unix" % sys.argv[0])

# --------------------------------------- PAC Parser ------------------------------------------- # 
# Taken some of the code from the Px project
# https://github.com/genotrance/px/blob/master/px.py

# Windows version
#  6.1 = Windows 7
#  6.2 = Windows 8
#  6.3 = Windows 8.1
# 10.0 = Windows 10

DEFAULT_USER_AGENT = 'besoCurl/ver 0.3'

if platform.system() == "Windows":
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
        ctypes.wintypes.LPCWSTR("Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"),
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

def winttp_detect_auto_proxy_config_url(target_url): # Setup 
    ACCESS_TYPE = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
    if WIN_VERSION < 6.3:
        ACCESS_TYPE = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
        
    hSession = ctypes.windll.winhttp.WinHttpOpen(
    ctypes.wintypes.LPCWSTR("Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"),
    ACCESS_TYPE, WINHTTP_NO_PROXY_NAME,
    WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC)

    pAutoProxyOptions = WINHTTP_AUTOPROXY_OPTIONS()
    pProxyInfo = WINHTTP_PROXY_INFO()

    pAutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
    pAutoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
    pAutoProxyOptions.lpszAutoConfigUrl = 0
    lpcwszUrl = ctypes.wintypes.LPCWSTR(target_url)
    result = ctypes.windll.winhttp.WinHttpGetProxyForUrl(hSession, lpcwszUrl, ctypes.byref(pAutoProxyOptions),
                                                            ctypes.byref(pProxyInfo))
    if result == False:

        dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
        ppwszAutoConfigUrl = ctypes.wintypes.LPWSTR()
        result = ctypes.windll.winhttp.WinHttpDetectAutoProxyConfigUrl(dwAutoDetectFlags, 
                                                                        ctypes.byref(ppwszAutoConfigUrl))

        if result == False:
            pass
        else:
            pAutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
            pAutoProxyOptions.dwAutoDetectFlags = 0
            pAutoProxyOptions.fAutoLogonIfChallenged = True
            pAutoProxyOptions.lpszAutoConfigUrl = ppwszAutoConfigUrl
            result = ctypes.windll.winhttp.WinHttpGetProxyForUrl(hSession, lpcwszUrl, ctypes.byref(pAutoProxyOptions),
                                                                    ctypes.byref(pProxyInfo))
            if result:
                proxy_final = pProxyInfo.lpszProxy.replace(" ", ",").replace(";", ",").replace(",DIRECT", "")
            else:
                pass
    else:
        proxy_final = pProxyInfo.lpszProxy.replace(" ", ",").replace(";", ",").replace(",DIRECT", "")
       

    return proxy_final


def how_to_go(url):
    proxies = []
    ieConfig = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
    ctypes.windll.winhttp.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(ieConfig)) # No need to save it into a variable
    if ieConfig.fAutoDetect:
        t = winttp_detect_auto_proxy_config_url(url)
        if "," in t:
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
        else:
            if t == 'DIRECT':
                return []
            else:
                for proxy in t:
                    proxy = proxy.split(":")
                    proxyip, proxyport = proxy[0], proxy[1]
                    t = proxyip, int(proxyport)
                    proxies.append(t) 

                return proxies        

    elif ieConfig.lpszAutoConfigUrl != None:
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

def initPyCURL(proxy_servers=[]):
    c = pycurl.Curl()

    if len(proxy_servers) > 0: # Only set proxy if a list was sent - otherwise just initliize curl 
        c.setopt(c.PROXY, proxy_servers[0][0])
        c.setopt(c.PROXYPORT, proxy_servers[0][1])
        c.setopt(c.PROXYAUTH, c.HTTPAUTH_ANY)
        # http://curl.haxx.se/mail/tracker-2010-10/0019.html
        #c.setopt(c.PROXYAUTH, c.HTTPAUTH_NTLM)
        c.setopt(c.PROXYUSERPWD, ":")
        
        c.setopt(c.HTTPPROXYTUNNEL, True) # tunnel to get to secure site.

    #c.setopt(c.FOLLOWLOCATION, True) # Follow Redirection - you can change to false, I made it so its enabled automaticly here // Edited to be enabled through method
    CURLOPT_ENCODING = getattr(c, 'ACCEPT_ENCODING', c.ENCODING)
    c.setopt(CURLOPT_ENCODING, '')
    c.setopt(c.FAILONERROR, False)
    c.setopt(c.COOKIEFILE, '')

    c.setopt(c.CAINFO, certifi.where())
    c.setopt(c.SSL_VERIFYPEER, 0)
    c.setopt(c.SSL_VERIFYHOST, 0)

    #def log(debug_type, debug_msg):
    #    print("[%d] %s" % (debug_type, debug_msg.decode('utf-8', 'backslashreplace').strip()))
    #c.setopt(c.VERBOSE, True)
    #c.setopt(c.DEBUGFUNCTION, log)

    return c
#==================================================================== CURL Init

# ----------------------------------- GET REQUEST CLASS ----------------------------------- # 
class get:
    def __init__(self, url, headers=[], proxies=None, proxy_pass=None,user_agent=DEFAULT_USER_AGENT, allow_redirect=False, auto_detect_proxy=False, username_pass=None):
        self.url = url
        self._response = None
        self._response_content = None        
        self._status_code = None
        self._headers_list = headers
        self._proxies = proxies
        self._proxy_pass = proxy_pass
        self._user_agent = user_agent
        self._allow_redirect = allow_redirect
        self._userpass = username_pass
        self.auto_detect_proxy = auto_detect_proxy
        self._retrieved_headers = io.BytesIO()


        self.request()

    @property
    def text(self):
        return self._response

    @property
    def status_code(self):
        return self._status_code

    @property
    def headers(self):
        return self._retrieved_headers.getvalue().decode()

    @property
    def content(self):
        return self._response_content

    def request(self):
        pycurl.global_init(pycurl.GLOBAL_WIN32)
        pycurl.global_init(pycurl.GLOBAL_SSL)
        buffer = io.BytesIO()
        if self.auto_detect_proxy == True:
            self._proxies = how_to_go(self.url)

        if self._proxies != None:
            c = initPyCURL(self._proxies)
        else:
            c = initPyCURL()
    
        if self._allow_redirect == False:
            c.setopt(c.FOLLOWLOCATION, False)
        elif self._allow_redirect == True:
            c.setopt(c.FOLLOWLOCATION, True)
        else:
            raise ValueError('allow_redirect must be true or false')
        if self._user_agent:
            c.setopt(c.USERAGENT, self._user_agent)
        if self._headers_list:
            c.setopt(pycurl.HTTPHEADER, self._headers_list)

        if self._userpass:
            c.setopt(c.HTTPAUTH, c.HTTPAUTH_NTLM)
            c.setopt(c.USERPWD, self._userpass)
        
        if self._proxy_pass:
            c.setopt(c.PROXYUSERPWD, self._proxy_pass)
            c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)

        c.setopt(c.HEADERFUNCTION, self._retrieved_headers.write)
        c.setopt(c.URL, self.url) 
        c.setopt(c.WRITEDATA, buffer)
        try:
            c.perform()
        except pycurl.error as e:
            e = str(e)
            if "returned error" in e:
                status_code = e[40:].split(' ')[0]
            else:
                raise pycurl.error(e)
        else:
            status_code = c.getinfo(c.RESPONSE_CODE) 

        c.close()
        body = buffer.getvalue()
        
        self._response_content = body
        self._response = body.decode('utf-8', 'ignore')
        try:
            self._status_code = int(status_code)
        except ValueError:
            self._status_code = int(status_code.split("'")[0])
# ----------------------------------- GET REQUEST CLASS END ----------------------------------- # 


# ----------------------------------- POST REQUEST CLASS ----------------------------------- # 
class post:
    def __init__(self, url, data=None, headers=[], proxies=None, user_agent=DEFAULT_USER_AGENT, allow_redirect=False, auto_detect_proxy=False, username_pass=None):
        self.url = url
        self._response = None
        self._response_content = None        
        self._status_code = None
        self.headers_list = headers
        self.proxies = proxies
        self.data = data
        self.userpass = username_pass        
        self.user_agent = user_agent
        self.allow_redirect = allow_redirect
        self._retrieved_headers = io.StringIO()
        self.auto_detect_proxy = auto_detect_proxy
        self._retrieved_headers = io.BytesIO()

        self.request()

    @property
    def text(self):
        return self._response

    @property
    def status_code(self):
        return self._status_code

    @property
    def headers(self):
        return self._retrieved_headers.getvalue().decode()

    @property
    def content(self):
        return self._response_content

    def request(self):
        pycurl.global_init(pycurl.GLOBAL_WIN32)
        pycurl.global_init(pycurl.GLOBAL_SSL)
        buffer = io.BytesIO()
        if self.auto_detect_proxy == True:
            self.proxies = how_to_go(self.url)

        if self.proxies != None:
            c = initPyCURL(self.proxies)
        else:
            c = initPyCURL()

        if self.userpass:
            c.setopt(c.HTTPAUTH, c.HTTPAUTH_NTLM)
            c.setopt(c.USERPWD, self.userpass)

        if self.allow_redirect == False:
            c.setopt(c.FOLLOWLOCATION, False)
        elif self.allow_redirect == True:
            c.setopt(c.FOLLOWLOCATION, True)
        else:
            raise ValueError('allow_redirect must be true or false')
        if self.user_agent:
            c.setopt(c.USERAGENT, self.user_agent)
        if self.headers_list:
            c.setopt(pycurl.HTTPHEADER, self.headers_list)


        c.setopt(c.HEADERFUNCTION, self._retrieved_headers.write)
        c.setopt(c.URL, self.url) 
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(c.POST, 1)
        if self.data:
            c.setopt(c.POSTFIELDS, self.data)
                
        
        try:
            c.perform()
        except pycurl.error as e:
            e = str(e)
            if "returned error" in e:
                status_code = e[40:].split(' ')[0]
            else:
                raise pycurl.error(e)
        else:
            status_code = c.getinfo(c.RESPONSE_CODE) 

        c.close()
        body = buffer.getvalue()

        self._response_content = body
        self._response = body.decode('utf-8', 'ignore')
        try:
            self._status_code = int(status_code)
        except ValueError:
            self._status_code = int(status_code.split("'")[0])
# ----------------------------------- POST REQUEST CLASS END ----------------------------------- # 

# ----------------------------------- PUT REQUEST CLASS START ----------------------------------- # 
class put:
    def __init__(self, url, data=None, headers=[], proxies=None, user_agent=DEFAULT_USER_AGENT, allow_redirect=False, auto_detect_proxy=False, username_pass=None):
        self.url = url
        self._response = None
        self._response_content = None        
        self._status_code = None
        self.headers_list = headers
        self.proxies = proxies
        self.data = data
        self.userpass = username_pass        
        self.user_agent = user_agent
        self.allow_redirect = allow_redirect
        self._retrieved_headers = io.StringIO()
        self.auto_detect_proxy = auto_detect_proxy
        self._retrieved_headers = io.BytesIO()

        self.request()

    @property
    def text(self):
        return self._response

    @property
    def status_code(self):
        return self._status_code

    @property
    def headers(self):
        return self._retrieved_headers.getvalue().decode()

    @property
    def content(self):
        return self._response_content

    def request(self):
        pycurl.global_init(pycurl.GLOBAL_WIN32)
        pycurl.global_init(pycurl.GLOBAL_SSL)
        buffer = io.BytesIO()
        if self.auto_detect_proxy == True:
            self.proxies = how_to_go(self.url)

        if self.proxies != None:
            c = initPyCURL(self.proxies)
        else:
            c = initPyCURL()

        if self.userpass:
            c.setopt(c.HTTPAUTH, c.HTTPAUTH_NTLM)
            c.setopt(c.USERPWD, self.userpass)

        if self.allow_redirect == False:
            c.setopt(c.FOLLOWLOCATION, False)
        elif self.allow_redirect == True:
            c.setopt(c.FOLLOWLOCATION, True)
        else:
            raise ValueError('allow_redirect must be true or false')
        if self.user_agent:
            c.setopt(c.USERAGENT, self.user_agent)
        if self.headers_list:
            c.setopt(pycurl.HTTPHEADER, self.headers_list)


        c.setopt(c.HEADERFUNCTION, self._retrieved_headers.write)
        c.setopt(c.URL, self.url) 
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(pycurl.CUSTOMREQUEST, "PUT")
        if self.data:
            c.setopt(c.POSTFIELDS, self.data)

        try:
            c.perform()
        except pycurl.error as e:
            e = str(e)
            if "returned error" in e:
                status_code = e[40:].split(' ')[0]
            else:
                raise pycurl.error(e)
        else:
            status_code = c.getinfo(c.RESPONSE_CODE) 
            
        c.close()
        body = buffer.getvalue()


        self._response_content = body
        self._response = body.decode('utf-8', 'ignore')
        try:
            self._status_code = int(status_code)
        except ValueError:
            self._status_code = int(status_code.split("'")[0])
# ----------------------------------- PUT REQUEST CLASS END ----------------------------------- # 

# ----------------------------------- DELETE REQUEST CLASS START ----------------------------------- # 
class delete:
    def __init__(self, url, headers=[], proxies=None, user_agent=DEFAULT_USER_AGENT, allow_redirect=False, auto_detect_proxy=False, username_pass=None):
        self.url = url
        self._response = None
        self._response_content = None
        self._status_code = None
        self.headers_list = headers
        self.proxies = proxies
        self.userpass = username_pass        
        self.user_agent = user_agent
        self.allow_redirect = allow_redirect
        self._retrieved_headers = io.StringIO()
        self.auto_detect_proxy = auto_detect_proxy
        self._retrieved_headers = io.BytesIO()

        self.request()

    @property
    def text(self):
        return self._response

    @property
    def status_code(self):
        return self._status_code

    @property
    def headers(self):
        return self._retrieved_headers.getvalue().decode()

    @property
    def content(self):
        return self._response_content

    def request(self):
        pycurl.global_init(pycurl.GLOBAL_WIN32)
        pycurl.global_init(pycurl.GLOBAL_SSL)
        buffer = io.BytesIO()
        if self.auto_detect_proxy == True:
            self.proxies = how_to_go(self.url)

        if self.proxies != None:
            c = initPyCURL(self.proxies)
        else:
            c = initPyCURL()

        if self.userpass:
            c.setopt(c.HTTPAUTH, c.HTTPAUTH_NTLM)
            c.setopt(c.USERPWD, self.userpass)

        if self.allow_redirect == False:
            c.setopt(c.FOLLOWLOCATION, False)
        elif self.allow_redirect == True:
            c.setopt(c.FOLLOWLOCATION, True)
        else:
            raise ValueError('allow_redirect must be true or false')
        if self.user_agent:
            c.setopt(c.USERAGENT, self.user_agent)
        if self.headers_list:
            c.setopt(pycurl.HTTPHEADER, self.headers_list)


        c.setopt(c.HEADERFUNCTION, self._retrieved_headers.write)
        c.setopt(c.URL, self.url) 
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(pycurl.CUSTOMREQUEST, "DELETE")
        try:
            c.perform()
        except pycurl.error as e:
            e = str(e)
            if "returned error" in e:
                status_code = e[40:].split(' ')[0]
            else:
                raise pycurl.error(e)
        else:
            status_code = c.getinfo(c.RESPONSE_CODE) 
            
        c.close()
        body = buffer.getvalue()


        self._response_content = body
        self._response = body.decode('utf-8', 'ignore')
        try:
            self._status_code = int(status_code)
        except ValueError:
            self._status_code = int(status_code.split("'")[0])

# ----------------------------------- DELETE REQUEST CLASS END ----------------------------------- #

class options:
    def __init__(self, url, headers=[], proxies=None, proxy_pass=None,user_agent=DEFAULT_USER_AGENT, allow_redirect=False, auto_detect_proxy=False, username_pass=None):
        self.url = url
        self._response = None
        self._response_content = None        
        self._status_code = None
        self._headers_list = headers
        self._proxies = proxies
        self._proxy_pass = proxy_pass
        self._user_agent = user_agent
        self._allow_redirect = allow_redirect
        self._userpass = username_pass
        self.auto_detect_proxy = auto_detect_proxy
        self._retrieved_headers = io.BytesIO()


        self.request()

    @property
    def text(self):
        return self._response

    @property
    def status_code(self):
        return self._status_code

    @property
    def headers(self):
        return self._retrieved_headers.getvalue().decode()

    @property
    def content(self):
        return self._response_content

    def request(self):
        pycurl.global_init(pycurl.GLOBAL_WIN32)
        pycurl.global_init(pycurl.GLOBAL_SSL)
        buffer = io.BytesIO()

        if self._proxies != None:
            c = initPyCURL(self._proxies)
        else:
            c = initPyCURL()
    
        if self._allow_redirect == False:
            c.setopt(c.FOLLOWLOCATION, False)
        elif self._allow_redirect == True:
            c.setopt(c.FOLLOWLOCATION, True)
        else:
            raise ValueError('allow_redirect must be true or false')
        if self._user_agent:
            c.setopt(c.USERAGENT, self._user_agent)
        if self._headers_list:
            c.setopt(pycurl.HTTPHEADER, self._headers_list)

        if self._userpass:
            c.setopt(c.HTTPAUTH, c.HTTPAUTH_NTLM)
            c.setopt(c.USERPWD, self._userpass)
        
        if self._proxy_pass:
            c.setopt(c.PROXYUSERPWD, self._proxy_pass)
            c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)

        c.setopt(c.HEADERFUNCTION, self._retrieved_headers.write)
        c.setopt(pycurl.CUSTOMREQUEST, "OPTIONS")
        c.setopt(c.URL, self.url) 
        c.setopt(c.WRITEDATA, buffer)
        try:
            c.perform()
        except pycurl.error as e:
            e = str(e)
            if "returned error" in e:
                status_code = e[40:].split(' ')[0]
            else:
                raise pycurl.error(e)
        else:
            status_code = c.getinfo(c.RESPONSE_CODE) 

        c.close()
        body = buffer.getvalue()
        
        self._response_content = body
        self._response = body.decode('utf-8', 'ignore')
        try:
            self._status_code = int(status_code)
        except ValueError:
            self._status_code = int(status_code.split("'")[0])

# ----------------------------------- SESSION CLASS ----------------------------------- # 
class Session:
    def __init__(self, headers=[], proxies=None, user_agent=DEFAULT_USER_AGENT, allow_redirect=False, auto_detect_proxy=False, username_pass=None):
        self._response = None
        self._status_code = None
        self.headers_list = headers
        self.user_agent = user_agent
        self.proxies = proxies
        self.userpass = username_pass        
        self.allow_redirect = allow_redirect
        self.auto_detect_proxy = auto_detect_proxy
        self._retrieved_headers = io.BytesIO()
        self._session_headers = io.BytesIO()

        raise NotImplementedError("Not Fully Implemented yet - Cannot be used")
    @property
    def text(self):
        return self._response

    @property
    def status_code(self):
        return self._status_code

    @property
    def headers(self):
        return self._retrieved_headers.getvalue().decode()


    def post(self, url, data=None, headers=[], proxies=None, user_agent=DEFAULT_USER_AGENT, allow_redirect=False, auto_detect_proxy=False):
        return post(url, data=data, headers=headers, proxies=proxies, user_agent=user_agent, allow_redirect=allow_redirect, auto_detect_proxy=auto_detect_proxy)


    def get(self, url, headers=None, proxies=None, user_agent=DEFAULT_USER_AGENT, allow_redirect=False, auto_detect_proxy=False):
        return get(url, headers=headers, proxies=proxies, user_agent=user_agent, allow_redirect=allow_redirect, auto_detect_proxy=auto_detect_proxy)

    

# ----------------------------------- SESSION CLASS END ----------------------------------- # 
