# besoCurl
A library for HTTP / HTTPs requests that supports SSPI and PAC file parsing(Automatic proxy settings detection)

besoCurl by Omri Baso  

Date: 21/10/2020  
All right reserved to Omri Baso for this library  
credits for pieces of code taken from other places are inside the code  

some code was taken from the Px project  
https://github.com/genotrance/px/blob/master/px.py  
# Dependencies:   
      pycurl-7.43.0.2  (I added the installiation for Windows that matchs python 3.6)  
      python 3.6 (due to Pycurl limitiation if you mannged to install it on 3.6+ it will also work)
      Installtion:  
      1. install pycurl-7.43.0.2.win-amd64-py3.6.exe
      2. pip install pycurl

# Teachnical Infomration  
the besoCurl project comes to make Pycurl more human usable while implmenting 
more automatic approch to the library, the library supports SSPI authentication to proxies over HTTP or HTTP(s) 
besoCurl as simple functions such as:  
```python  
import besoCurl

def main():  
    url = 'http://192.168.189.136/'
    useragents = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; Safari/537.36'  
    headers = ["Accept: OmriBeso", "Content-type: application/json"]  
    r = post(url, headers=headers, user_agent=useragents, auto_detect_proxy=True)  
    print(r['text'])  

main()  
```

OR for a post request

```python
import besoCurl

def main():
    url = 'http://192.168.189.136/'
    useragents = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; Safari/537.36'
    headers = ["Accept: OmriBeso", "Content-type: application/json"]
    r = besoCurl.post(url, data=data, headers=headers, user_agent=user_agent, auto_detect_proxy=True)
    print(r['text'])

main()    
```

NOTE: the get and post requests functions returns an object of a dictionary with text, and status_code
for example `print(r['text'])` or `print(r['status_code'])`

the code infront of you will return the HTML content of the url inserted into the function,  
user the User-Agent set to it and the headers. 
also - `auto_detect_proxy=True` will try to fetch the windows settings for accessing the internet. 
if a PAC file is configured it will download it and parse the Javascript in order for you go through   
the proxy, if a PAC file is configured AND a manual proxy is set, it will choose the PAC path instead.  
if only a manual proxy is set it will use it, if no proxy is configured i will not use any proxies and go directly to the internet.  

if a proxy is set, the HTTP request will use SSPI to authenticate to the proxy without entering any credentials.  
More Information about hopw it works: https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-provider-interface-sspi-  

In general i recommend to use `auto_detect_proxy=True` all the time.  

you can also set a proxy manully when invoking a request as the variables `proxies=("127.0.0.1", 8080)`  
proxies must have the format mentioned above.  

TODO:  
1. add WPAD (Auto Detect Settings support),  
2. add PUT method,  
3. and multipart forms on POST requests 
