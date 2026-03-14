import os

import requests
import base64

import csv

import sys

import tkinter as tk
from tkinter import messagebox

import socket

import whois
from datetime import datetime

import re               #regular expression
from urllib.parse import urlparse

#api key
API_KEY = "9bdc148209e95d2f0ccc009dae5a41b3d3e0dfdc96486265a302ebc249d1c43a"

def check_virustotal(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {
            "x-apikey": API_KEY
        }

        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats["malicious"]
            suspicious = stats["suspicious"]
            harmless = stats["harmless"]
            undetected = stats["undetected"]

            return f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}"

        else:
            return "No report in VirusTotal"

    except:
        return "VirusTotal check failed"

#colours
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


print(BLUE + "=== Suspicious URL Detector ===" + RESET)

#def detect_url(url):



# for enter url or stop it

#while True:

if len(sys.argv) > 1:
        url = sys.argv[1]
else:
        url = input("Enter a URL ( or type 'exit' to quit): ")
print(BLUE +"\n URL INFORMATION"+RESET)

if url.lower() == "exit":
        print("Exiting URL detector...")


#to identify domain , subdomain,tld
parsed = urlparse(url)
host = parsed.netloc
host_parts = host.split(".")

if len(host_parts) >=2:
        tld = host_parts[-1]
        main_domain = host_parts[-2] + "." + host_parts[-1]
        subdomains = host_parts[:2]
else:
        tld = "unknown"
        main_domain = host
        subdomains = []

subdomain_count = len(subdomains)

#whois
domain_age_days = None

try:
        domain_info = whois.whois(main_domain)
        creation_date = domain_info.creation_date

        print("Main_domain:", main_domain)
        print("Creation_date:",creation_date)

        if isinstance(creation_date, list):
                creation_date = creation_date[0]
        if creation_date:
                domain_age_days = (datetime.now() - creation_date).days
except:
        domain_age_days = None
# check DNS

try:
        ip_address = socket.gethostbyname(main_domain)
        print("Resolved IP:", ip_address)
except:
        print("DNS resolution failed")
        warning.append("no resolve in DNS")
        score += 2

#keywords print and defaulf

score = 0
warning = []

with open("keywords.txt","r") as file:
        phishing_keywords = [line.strip() for line in file if line.strip()]

suspicious = False

# Check 1: URL length
if len(url) > 30:
        warning.append("Warning: URL is very long")
        suspicious = True
        score +=1

# Check 2: @ symbol
if "@" in url:
        warning.append("URL contains @ symbol")
        suspicious = True
        score +=1

# Check 3: hyphen
if "-" in url:
        warning.append("URL contains hyphen (-)")
        suspicious = True
        score +=1

# Check 4: HTTPS
if not url.startswith("https://"):
        warning.append("URL is not using HTTPS")
        suspicious = True
        score +=1

# ipv4 detection block
if re.search(r"\d+\.\d+\.\d+\.\d+",url):
        warning.append("URL contain an ipv4 ")
        score +=1
        suspicious = True

#ipv6 detection block
elif re.search(r"\[[0-9a-fA-F:]+\]", url):
        warning.append("URL contains an ipv6 ")
        score += 1
        suspicious = True

# keyword detection
found_keywords = []
for word in phishing_keywords:
        if word in url.lower():
                found_keywords.append(word)
if found_keywords:
        warning.append(f"suspicious keyword: " + ", ".join(found_keywords))
        score +=1
        suspicious = True

#dot detection

dot_count = url.count(".")

if dot_count > 3:
        warning.append(" too many dots ")
        score += 1
        suspicious = True

#subdomain

if subdomain_count > 2:
        warning.append("URL contain many subdomains")
        score += 1
        suspicious = True

#whois check
if domain_age_days is not None and domain_age_days < 180:
        warnings.append("Domain is very new ")
        score += 1
        suspicious = True

vt_result = check_virustotal(url)
print("VirusTotal:", vt_result)

# Final result
if suspicious:
        print(RED +"\nResult: This URL looks suspicious"+RESET)
else:
        print(GREEN +"\nResult: This URL looks safe"+RESET)
# save scan result to file
report = f"""
URL: {url}
Host: {host}
Main Domain: {main_domain}
TLD: {tld}
Domain Age (days): {domain_age_days if domain_age_days is not None else "Unknown"}
Domain Creation Date: {creation_date if 'creation_date' in locals() else "Unknown"}
Resolved IP: {ip_address if 'ip_address' in locals() else "Not resolved"}

Subdomains: {", ".join(subdomains) if subdomains else "None"}
Subdomain Count: {subdomain_count}

Warning:
{chr(10).join("- " + w for w in warning) if warning else "None"}

Risk Score: {score}
        """

with open("scan_results.txt", "a") as file:
        file.write(report)
        file.write("\n" + "="*40 + "\n")

# csv save


file_exists = os.path.isfile("scan_results.csv")

with open("scan_results.csv", "a", newline="") as csvfile:
    writer = csv.writer(csvfile)

    if not file_exists:
        writer.writerow([
            "URL",
            "Host",
            "Main Domain",
            "TLD",
            "Domain Age (days)",
            "Domain Creation Date",
            "Subdomains",
            "Subdomain Count",
            "Warnings",
            "Risk Score",
            "VirusTotal"
        ])

    writer.writerow([
        url,
        host,
        main_domain,
        tld,
        domain_age_days if domain_age_days is not None else "Unknown",
        creation_date if 'creation_date' in locals() else "Unknown",
        "|".join(subdomains) if subdomains else "None",
        subdomain_count,
        "|".join(warning) if warning else "None",
        score
    ])

# print analysis report

print(BLUE+"\n--- Analysis Report ---"+RESET)
print("URL:", url)

                           #domain,subdomain result

print("Host:",host)
print("Main Domain:", main_domain)
print("TLD:",tld)

print("Domain Age (days):", domain_age_days if domain_age_days is not None else "Unknown")

if subdomains:
        print("Subdomains:",".".join(subdomains))
else:
        print("SubDomains: None")

print ("Subdomain Count:", subdomain_count)

if warning:
        print(RED +"\nwarning:"+RESET)
        for w in warning:
                print("-", w)
else:
        print(GREEN+"\nwarning; None"+RESET)


# print score
print("\nRisk Score:",score)

if score == 0:
        print(GREEN +"Risk level:safe"+RESET)
elif score <=2:
        print(YELLOW +"Risk Level:Medium Risk"+RESET)
else:
        print(RED +"Risk Level:High Risk"+RESET)

print("\n")
