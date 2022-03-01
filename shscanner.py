import requests
import os
import sys, getopt
import time
import termcolor
import webbrowser
import platform
import urllib.request
import urllib.error
import urllib.parse

client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0)\
 Gecko/20100101 Firefox/53.0',
    'Accept': 'text/html,application/xhtml+xml,\
 application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US;q=0.8,en;q=0.3',
    'Upgrade-Insecure-Requests': 1
 }

headerbook = ["strict-transport-security", "content-security-policy", "x-xss-protection", "x-frame-options", "x-content-type-options", "x-permitted-cross-domain-policies", "referrer-policy", "clear-site-data", "cross-origin-embedder-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "cache-control", "permissions-policy"]

class Tcolor:
    INFO = '\033[36m' #BLUE
    WARNING = '\033[93m' #YELLOW
    MISSING = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR
    SUCCESS = '\033[32m' #GREEN
def is_https(target):
    return target.startswith('https://')

def scan(url, updateList=[]):
    print("Scanning: ", url, "\n")
    #rep = requests.head(url)
    #head = rep.headers
    availHead=[]
    request = urllib.request.Request(url, headers=client_headers)
    response = urllib.request.urlopen(request, timeout=10)
    head = response.getheaders()
   

    
    
    for header, status in head:
        lower_header = header.lower()
        
        if lower_header in headerbook:
            
            
            availHead.append(lower_header)
            ##print(f"{Tcolor.INFO}[INFO]{Tcolor.RESET}",header, ".......[is set to: ",status,"]")
            print(f"{Tcolor.INFO}[INFO]{Tcolor.RESET}" ,'{:.<40s} {:<10}'.format(header,status))
            time.sleep(0.7)
    print("")
    for i in headerbook:
        if i not in availHead:
            print(f"{Tcolor.WARNING}[WARNING]{Tcolor.RESET}",'{:.<40s} {:<10}'.format(i, f"{Tcolor.MISSING}IS MISSING{Tcolor.RESET}"))
            updateList.append(i)
            time.sleep(0.2)
    print(f"\n{Tcolor.SUCCESS}SUCCESSFULLY SCANNED!{Tcolor.RESET}\n")
    return updateList



def recommendation(misshead):
    switch = input("Would you like to view recommendations?[Y/n] ")
    recommendDict = {
        "strict-transport-security" : " \nis a web security policy mechanism which helps to protect websites against protocol downgrade attacks and cookie hijacking.\n\n Sample options: \n\nmax-age=SECONDS | includeSubDomains \n\n Ex usage: Strict-Transport-Security: max-age=31536000",
        "x-frame-options" : "\nimproves the protection of web applications against clickjacking.\n\n Sample options: \n\ndeny - No rendering within a frame\nsameorigin - No rendering if origin mismatch \n allow-from: DOMAIN - Allows rendering if framed by frame loaded from DOMAIN\n\n ex usage: X-Frame-Options: deny",
        "x-content-type-options" : "\n will prevent the browser from interpreting files as a different MIME type to what is specified in the Content-Type HTTP header\n\n Sample options: \n\nnosniff - Will prevent the browser from MIME-sniffing a response away from the declared content-type\n\n Ex usage: X-Content-Type-Options: nosniff",
        "content-security-policy" : "\nequires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browsers render pages\n\n Sample options: \n\nscript-src - Define which scripts the protected resource can execute \n\n Ex usage: Content-Security-Policy: script-src 'self'",
        "x-permitted-cross-domain-policies" : "\nA cross-domain policy file is an XML document that grants a web client, such as Adobe Flash Player or Adobe Acrobat\n\n Sample options: \n\nmaster-only - Only this master policy file is Allowed \n by-content-type - [HTTP/HTTPS only] Only policy files served with Content-Type: text/x-cross-domain-policy are allowed. \n\n Ex usage: X-Permitted-Cross-Domain-Policies: master-only",
        "referrer-policy" : "\ngoverns which referrer information, sent in the Referer header, should be included with requests made.\n\n Sample options: \n\n no-referrer - The Referer header will be omitted entirely. No referrer information is sent along with requests. \n no-referrer-when-downgrade - This is the user agent's default behavior if no policy is specified. The origin is sent as referrer to a-priori as-much-secure destination (HTTPS → HTTPS), but isn't sent to a less secure destination (HTTPS → HTTP).\n\n Ex usage: Referrer-Policy: no-referrer",
        "clear-site-data" : "\nclears browsing data (cookies, storage, cache) associated with the requesting website.\n\n Sample options: \n\n cache - Indicates that the server wishes to remove locally cached data for the origin of the response URL. \n cookies - Indicates that the server wishes to remove all cookies for the origin of the response URL. HTTP authentication credentials are also cleared out. This affects the entire registered domain, including subdomains. \n storage - Indicates that the server wishes to remove all DOM storage for the origin of the response URL. \n\n Ex Usage: Clear-Site-Data: 'cache','cookies','storage'",
        "cross-origin-embedder-policy" : "\nThis response header (also named COEP) prevents a document from loading any cross-origin resources that don’t explicitly grant the document permission\n\n Sample options: \n\n unsafe-none - Allows the document to fetch cross-origin resources without giving explicit permission through the CORS protocol or the Cross-Origin-Resource-Policy header \n require-corp - A document can only load resources from the same origin, or resources explicitly marked as loadable from another origin. \n\n Ex usage: Cross-Origin-Embedder-Policy: require-corp",
        "cross-origin-opener-policy" : "\nThis response header (also named COOP) allows you to ensure a top-level document does not share a browsing context group with cross-origin documents.\n\n Sample options: \n\n same-origin - Isolates the browsing context exclusively to same-origin documents. Cross-origin documents are not loaded in the same browsing context. \n same-origin-allow-popups - Retains references to newly opened windows or tabs which either don't set COOP or which opt out of isolation by setting a COOP of unsafe-none. \n\n Ex usage: Cross-Origin-Opener-Policy: same-origin",
        "cross-origin-resource-policy" : "\nThis response header (also named CORP) allows to define a policy that lets web sites and applications opt in to protection against certain requests from other origins\n\n Sample options: \n\n same-site - Only requests from the same Site can read the resource. \n same-origin - Only requests from the same Origin (i.e. scheme + host + port) can read the resource. \n cross-origin - Requests from any Origin (both same-site and cross-site) can read the resource. Browsers are using this policy when an CORP header is not specified. \n\n Ex usage: Cross-Origin-Resource-Policy: same-origin",
        "cache-control" : "\nThis header holds directives (instructions) for caching in both requests and responses.\n\n Sample options: \n\n no-cache - The response may be stored by any cache, even if the response is normally non-cacheable. However, the stored response MUST always go through validation with the origin server first before using it. \n no-store - The response may not be stored in any cache. \n\n Ex usage: Cache-Control: no-store, max-age=0",
        "x-xss-protection" : "\nhe X-XSS-Protection header has been deprecated by modern browsers and its use can introduce additional security issues on the client side\n\n Sample options: \n\n 0 - Filter Disabled \n 1 - Filter enabled. If a cross-site scripting attack is detected, in order to stop the attack, the browser will sanitize the page. \n\n Ex usage: X-XSS-Protection: 1",
        "permissions-policy" : "\n\n Sample options: \n\n please refer to the link below for this header"
    }
    if switch == "Y" or switch == "y":
        print("\n----------------------------------------------------------------------------------------------------")
        for items in misshead:
            
            if items in recommendDict.keys():
                
                print(f"{Tcolor.INFO}{items}{Tcolor.RESET}",": ", recommendDict[items], "\n")
                print("----------------------------------------------------------------------------------------------------")
        print("Please read more detailed info about implementing Security Headers through this link: \n\nhttps://owasp.org/www-project-secure-headers/\n")
        os._exit(0)
       

            
    else:
        os._exit(0)

def detectOs():
    os_name = platform.system()
    if os_name == "Windows":
        os.system("color")

missingHeaders=[]

def start(argv):
    try:
        opts, args = getopt.getopt(argv,"u:h") 
    except getopt.error as err:
        print((str(err)))
        print("\nUsage: python3 shscanner.py -u <url>")
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            print("\nUsage: python3 shscanner.py -u <url>")
            sys.exit()
        elif opt in ("-u"):
            
            detectOs()
            scan(arg, missingHeaders)
            recommendation(missingHeaders)
        elif len(opt) == 0:
            print("\nUsage: python3 shscanner.py -u <url>")

validate = len(sys.argv)

if validate <= 1:
    
    print("No options and parameters specified \n\n Usage: python3 shscanner.py -u <url>")
    sys.exit()
else:
    start(sys.argv[1:])






