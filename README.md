# Suspicious URL Detector

A Python-based cybersecurity tool that analyzes URLs and detects potentially suspicious or phishing-like patterns.

## Features
- Detects phishing keywords in URLs
- Detects IP-based URLs
- Extracts domain, main domain, and TLD
- Detects excessive subdomains
- Calculates a risk score
- Performs DNS/hostname resolution
- Checks domain age using WHOIS
- Allows scanning of multiple URLs
- Saves scan results into a CSV report
- Integrates with threat intelligence APIs for reputation checking

## Technologies Used
- Python
- WHOIS lookup
- DNS resolution
- Threat intelligence API (VirusTotal / Safe Browsing)

## Purpose
This project was built to practice cybersecurity analysis and understand how suspicious URLs can be identified using automated detection techniques.

## Output
The tool generates:
- Suspicious indicators
- Domain information
- Risk score
- CSV report for analysis
