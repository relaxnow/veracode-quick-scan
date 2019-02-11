Veracode Quick Scan
===================

A quick and dirty example of using Veracode APIs to scan a couple of files.
This works best with files from applications written in dynamic languages like PHP or JavaScript.

Example Usage in Bash (Unix systems):
```
$ export VCUID=my_veracode_api_username
$ export VCPWD=my_veracode_api_password
$ veracode-quick-scan quickscan --appid=288128 --sandboxid=1004849 MyProject/index.php 
Starting upload
Starting prescan with autoscan
Waiting on results... (BUILD: 3549203)
Waiting on results... (BUILD: 3549203)
Waiting on results... (BUILD: 3549203)
Waiting on results... (BUILD: 3549203)
Waiting on results... (BUILD: 3549203)
Very High | Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') | index.php:366
Very High | Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') | index.php:385
Medium | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) | index.php:318
Medium | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) | index.php:319
Medium | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) | index.php:407
Medium | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) | index.php:496
Scan took 00:03:44. Total number of flaws found: 6
``` 

Please note that this is not a replacement for 
a full Static Analysis scan (which will give higher quality results), 
nor for Veracode Greenlight (proper IDE support).

Requirements
------------
* PHP 7.1+
* [API User](https://help.veracode.com/reader/LMv_dtSHyb7iIxAQznC~9w/QNoab55SG7moI54f5vU5KQ)
* appid and sandboxid 

To find the appid and sandboxid:
1. Go to [Veracode Platform](https://analysiscenter.veracode.com).
2. Go to "My Portfolio" and then "Applications".
3. Click on the application link.
4. Go to "Sandboxes" in the menu on the left hand side.
5. Click on the sandbox you'd like to use for Quick Scan or create a new sandbox.
6. Make sure you have "Sandbox Scans" selected in the menu on the left hand side 
   and the URL looks like this:
   https://analysiscenter.veracode.com/auth/index.jsp#SandboxView:123:456:789
7. The appid is the second part ("456") in from this URL, 
   the sandboxid is third party ("789") from this URL.
