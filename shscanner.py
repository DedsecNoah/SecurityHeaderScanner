import requests
import os
import sys, getopt
import time
import termcolor
import webbrowser


headerbook = ["Strict-Transport-Security", "Content-Security-Policy", "X-XSS-Protection", "X-Frame-Options", "X-Content-Type-Options", "X-Permitted-Cross-Domain-Policies", "Referrer-Policy", "Clear-Site-Data", "Cross-Origin-Embedder-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Cache-Control", "Permissions-Policy"]

class Tcolor:
    INFO = '\033[36m' #GREEN
    WARNING = '\033[93m' #YELLOW
    MISSING = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR
    SUCCESS = '\033[32m'

def scan(url, updateList=[]):
    print("Scanning: ", url, "\n")
    rep = requests.head(url)
    head = rep.headers
    availHead=[]
    
    for header, status in head.items():
        if header in headerbook:
            availHead.append(header)
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
        "Strict-Transport-Security" : "\n max-age=SECONDS | includeSubDomains \n\n Ex usage: Strict-Transport-Security: max-age=31536000",
        "X-Frame-Options" : "\n deny - No rendering within a frame\nsameorigin - No rendering if origin mismatch \n allow-from: DOMAIN - Allows rendering if framed by frame loaded from DOMAIN\n\n ex usage: X-Frame-Options: deny",
        "X-Content-Type-Options" : "\n nosniff - Will prevent the browser from MIME-sniffing a response away from the declared content-type\n\n Ex usage: X-Content-Type-Options: nosniff",
        "Content-Security-Policy" : "\n script-src - Define which scripts the protected resource can execute \n\n Ex usage: Content-Security-Policy: script-src 'self'",
        "X-Permitted-Cross-Domain-Policies" : "\n master-only - Only this master policy file is Allowed \n by-content-type - [HTTP/HTTPS only] Only policy files served with Content-Type: text/x-cross-domain-policy are allowed. \n\n Ex usage: X-Permitted-Cross-Domain-Policies: master-only",
        "Referrer-Policy" : "\n no-referrer - The Referer header will be omitted entirely. No referrer information is sent along with requests. \n no-referrer-when-downgrade - This is the user agent's default behavior if no policy is specified. The origin is sent as referrer to a-priori as-much-secure destination (HTTPS → HTTPS), but isn't sent to a less secure destination (HTTPS → HTTP).\n\n Ex usage: Referrer-Policy: no-referrer",
        "Clear-Site-Data" : "\n cache - Indicates that the server wishes to remove locally cached data for the origin of the response URL. \n cookies - Indicates that the server wishes to remove all cookies for the origin of the response URL. HTTP authentication credentials are also cleared out. This affects the entire registered domain, including subdomains. \n storage - Indicates that the server wishes to remove all DOM storage for the origin of the response URL. \n\n Ex Usage: Clear-Site-Data: 'cache','cookies','storage'",
        "Cross-Origin-Embedder-Policy" : "\n unsafe-none - Allows the document to fetch cross-origin resources without giving explicit permission through the CORS protocol or the Cross-Origin-Resource-Policy header \n require-corp - A document can only load resources from the same origin, or resources explicitly marked as loadable from another origin. \n\n Ex usage: Cross-Origin-Embedder-Policy: require-corp",
        "Cross-Origin-Opener-Policy" : "\n same-origin - Isolates the browsing context exclusively to same-origin documents. Cross-origin documents are not loaded in the same browsing context. \n same-origin-allow-popups - Retains references to newly opened windows or tabs which either don't set COOP or which opt out of isolation by setting a COOP of unsafe-none. \n\n Ex usage: Cross-Origin-Opener-Policy: same-origin",
        "Cross-Origin-Resource-Policy" : "\n same-site - Only requests from the same Site can read the resource. \n same-origin - Only requests from the same Origin (i.e. scheme + host + port) can read the resource. \n cross-origin - Requests from any Origin (both same-site and cross-site) can read the resource. Browsers are using this policy when an CORP header is not specified. \n\n Ex usage: Cross-Origin-Resource-Policy: same-origin",
        "Cache-Control" : "\n no-cache - The response may be stored by any cache, even if the response is normally non-cacheable. However, the stored response MUST always go through validation with the origin server first before using it. \n no-store - The response may not be stored in any cache. \n\n Ex usage: Cache-Control: no-store, max-age=0",
        "X-XSS-Protection" : "\n 0 - Filter Disabled \n 1 - Filter enabled. If a cross-site scripting attack is detected, in order to stop the attack, the browser will sanitize the page. \n\n Ex usage: X-XSS-Protection: 1",
        "Permissions-Policy" : "\n please refer to the link below for this header"
    }
    if switch == "Y":
        print("\n--------------------------------------------------")
        for items in misshead:
            
            if items in recommendDict.keys():
                
                print(f"{Tcolor.INFO}{items}{Tcolor.RESET}",": ", recommendDict[items], "\n")
                print("--------------------------------------------------")
        print("Please read more detailed info about implementing Security Headers through this link: https://owasp.org/www-project-secure-headers/")
        command = input("Proceed with the link now?[Y/n]")
        if command == "Y":
            webbrowser.open("https://owasp.org/www-project-secure-headers")
        else:
            os._exit(0)


            
    else:
        os._exit(0)
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
            os.system('cls')
            scan(arg, missingHeaders)
            recommendation(missingHeaders)
        elif len(opt) == 0:
            print("\nUsage: python3 shscanner.py -u <url>")

validate = len(sys.argv)

if validate <= 1:
    
    print("\nNo options and parameters specified \n -h for usage")
    sys.exit()
else:
    start(sys.argv[1:])
    






