# SecurityHeaderScanner

Python Script to check website's Security Headers


### Usage

```
C:\Users\User> python3 shscanner.py -h
-u To specify url
-h For help

usage: shscanner [-u] <url>
```

### Output

```
Scanning:  https://www.example.com

[INFO] Cache-Control........................... no-store, no-cache, must-revalidate
[INFO] X-XSS-Protection........................ 1
[INFO] X-Frame-Options......................... SAMEORIGIN
[INFO] X-Content-Type-Options.................. nosniff

[WARNING] Strict-Transport-Security............... IS MISSING
[WARNING] Content-Security-Policy................. IS MISSING
[WARNING] X-Permitted-Cross-Domain-Policies....... IS MISSING
[WARNING] Referrer-Policy......................... IS MISSING
[WARNING] Clear-Site-Data......................... IS MISSING
[WARNING] Cross-Origin-Embedder-Policy............ IS MISSING
[WARNING] Cross-Origin-Opener-Policy.............. IS MISSING
[WARNING] Cross-Origin-Resource-Policy............ IS MISSING
[WARNING] Permissions-Policy...................... IS MISSING

SUCCESSFULLY SCANNED!

Would you like to view recommendations?[Y/n]
```

### Dependencies
run setup.py

Ex: python3 setup.py


  
