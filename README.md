# Metamap
Nmap/Vulners Automated Vulnerability Scanner

This tool takes the output of an nmap version scan and searches the https://vulners.com database for known vulnerabilities.

## Installation
```
git clone https://github.com/unknwncharlie/Metamap.git
cd Metamap
pip3 install -r requirements.txt
```

## Usage 
```python3 metamap.py [args] target```

### Arguments
You can pass any Nmap arguments to refine your query.

### Example
```python3 metamap.py -p22,23,80,8080 -T4 192.168.1.10```

### Results
```
user@ubuntu:~/Metamap/$ python3 main.py 192.168.1.10

  __  __ ______ _______       __  __          _____
 |  \/  |  ____|__   __|/\   |  \/  |   /\   |  __ \
 | \  / | |__     | |  /  \  | \  / |  /  \  | |__) |
 | |\/| |  __|    | | / /\ \ | |\/| | / /\ \ |  ___/
 | |  | | |____   | |/ ____ \| |  | |/ ____ \| |
 |_|  |_|______|  |_/_/    \_\_|  |_/_/    \_\_|
====================================================

Nmap/Vulners Automated Vulnerability scanning tool

Author: @su__charlie

====================================================
You need to provide a Vulners API key. 
You can get one here: https://vulners.com/

Vulners API Key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

Showing 1 results from Metamap Scan

Scan results for (192.168.1.10)
tcp/80                  open                http/Apache httpd 2.4.41
	CVE-2020-1934: Apache Httpd < None: mod_proxy_ftp use of uninitialized value
	CVE-2020-1927: Apache Httpd < None: mod_rewrite CWE-601 open redirect
tcp/631                 open                ipp/CUPS 2.3
tcp/8300                open                http/Apache httpd 

Command /usr/bin/nmap -oX - -sV 192.168.1.10 executed in 11.60 seconds.
```

