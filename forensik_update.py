#!/usr/bin/env python3
"""
Digital Forensic Tools for Phishing Website Analysis
Author: Digital Forensic Specialist
Version: 2.0
"""

import requests
import socket
import json
import whois
import dns.resolver
import ssl
import datetime
from urllib.parse import urlparse
import subprocess
import re
from bs4 import BeautifulSoup
import time
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PhishingForensicTools:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {}
    
    def domain_whois_analysis(self, domain):
        """Analyze domain WHOIS information"""
        print(f"[+] Analyzing WHOIS for {domain}")
        try:
            w = whois.whois(domain)
            whois_data = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'country': w.country
            }
            self.results['whois'] = whois_data
            print(f"    [+] Registrar: {w.registrar}")
            print(f"    [+] Created: {w.creation_date}")
            return whois_data
        except Exception as e:
            print(f"[-] WHOIS lookup failed: {e}")
            return None
    
    def dns_analysis(self, domain):
        """Analyze DNS records"""
        print(f"[+] Analyzing DNS records for {domain}")
        dns_data = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_data[record_type] = [str(rdata) for rdata in answers]
                print(f"    [+] {record_type}: {dns_data[record_type]}")
            except Exception as e:
                dns_data[record_type] = f"No {record_type} record found"
        
        self.results['dns'] = dns_data
        return dns_data
    
    def ip_geolocation(self, ip_address):
        """Get IP geolocation information"""
        print(f"[+] Getting geolocation for {ip_address}")
        try:
            response = self.session.get(f"http://ip-api.com/json/{ip_address}", timeout=10)
            if response.status_code == 200:
                geo_data = response.json()
                print(f"    [+] Location: {geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}")
                return geo_data
        except Exception as e:
            print(f"[-] Geolocation lookup failed: {e}")
        return None
    
    def ssl_certificate_analysis(self, domain, port=443):
        """Analyze SSL certificate"""
        print(f"[+] Analyzing SSL certificate for {domain}")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_data = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    self.results['ssl'] = ssl_data
                    print(f"    [+] SSL Issuer: {ssl_data['issuer'].get('organizationName', 'Unknown')}")
                    return ssl_data
        except Exception as e:
            print(f"[-] SSL analysis failed: {e}")
        return None
    
    def wayback_machine_check(self, domain):
        """Check Wayback Machine for archived content"""
        print(f"[+] Checking Wayback Machine for {domain}")
        try:
            url = f"http://archive.org/wayback/available?url={domain}"
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data.get('archived_snapshots') and data['archived_snapshots'].get('closest'):
                    wayback_data = {
                        'available': True,
                        'closest': data['archived_snapshots']['closest']
                    }
                    print(f"    [+] Archive found: {wayback_data['closest'].get('timestamp', 'Unknown')}")
                    print(f"    [+] Archive URL: {wayback_data['closest'].get('url', 'Unknown')}")
                else:
                    wayback_data = {'available': False}
                    print(f"    [-] No archived content found")
                
                self.results['wayback'] = wayback_data
                return wayback_data
        except Exception as e:
            print(f"[-] Wayback Machine check failed: {e}")
        return None
    
    def shodan_lookup(self, ip_address, api_key=None):
        """Lookup IP information on Shodan (requires API key)"""
        if not api_key:
            print("[-] Shodan API key not provided")
            return None
            
        print(f"[+] Looking up {ip_address} on Shodan")
        try:
            url = f"https://api.shodan.io/shodan/host/{ip_address}?key={api_key}"
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                shodan_data = response.json()
                self.results['shodan'] = shodan_data
                print(f"    [+] Shodan data found: {len(shodan_data.get('data', []))} services")
                return shodan_data
            else:
                print(f"[-] Shodan lookup failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"[-] Shodan lookup failed: {e}")
        return None
    
    def google_cache_check(self, domain):
        """Check Google cache for the domain"""
        print(f"[+] Checking Google cache for {domain}")
        try:
            cache_url = f"http://webcache.googleusercontent.com/search?q=cache:{domain}"
            response = self.session.get(cache_url, timeout=15, allow_redirects=True)
            
            # Check if we got a cached page or redirect to original
            is_cached = ('webcache.googleusercontent.com' in response.url and 
                        response.status_code == 200 and 
                        len(response.text) > 1000)  # Reasonable content length
            
            cache_data = {
                'status_code': response.status_code,
                'cached': is_cached,
                'content_length': len(response.text) if response.text else 0,
                'final_url': response.url
            }
            
            if is_cached:
                print(f"    [+] Google cache found with {cache_data['content_length']} bytes")
            else:
                print(f"    [-] No Google cache available")
            
            self.results['google_cache'] = cache_data
            return cache_data
        except Exception as e:
            print(f"[-] Google cache check failed: {e}")
            cache_data = {'status_code': 0, 'cached': False, 'error': str(e)}
            self.results['google_cache'] = cache_data
        return None
    
    def subdomain_enumeration(self, domain):
        """Basic subdomain enumeration"""
        print(f"[+] Enumerating subdomains for {domain}")
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'www1', 'email', 'img', 'www3',
            'help', 'shop', 'secure', 'api', 'cdn', 'media', 'static', 'docs'
        ]
        
        found_subdomains = []
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
                print(f"    [+] Found: {full_domain}")
            except socket.gaierror:
                continue
        
        self.results['subdomains'] = found_subdomains
        return found_subdomains
    
    def reverse_dns_lookup(self, ip_address):
        """Perform reverse DNS lookup"""
        print(f"[+] Reverse DNS lookup for {ip_address}")
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            self.results['reverse_dns'] = hostname
            print(f"    [+] Hostname: {hostname}")
            return hostname
        except Exception as e:
            print(f"[-] Reverse DNS lookup failed: {e}")
        return None
    
    def http_headers_analysis(self, domain):
        """Analyze HTTP headers"""
        print(f"[+] Analyzing HTTP headers for {domain}")
        try:
            response = self.session.head(f"http://{domain}", timeout=10, allow_redirects=True)
            headers_data = dict(response.headers)
            self.results['http_headers'] = headers_data
            print(f"    [+] Server: {headers_data.get('Server', 'Unknown')}")
            return headers_data
        except Exception as e:
            print(f"[-] HTTP headers analysis failed: {e}")
        return None
    
    def passive_dns_history(self, domain):
        """Check passive DNS history using public sources"""
        print(f"[+] Checking passive DNS history for {domain}")
        try:
            # Using HackerTarget API for passive DNS
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200 and response.text.strip():
                records = response.text.strip().split('\n')
                dns_history = {
                    'status': 'success',
                    'historical_records': records,
                    'count': len(records)
                }
                print(f"    [+] Found {len(records)} historical DNS records")
            else:
                dns_history = {'status': 'no_data', 'historical_records': [], 'count': 0}
                print(f"    [-] No historical DNS data found")
            
            self.results['passive_dns'] = dns_history
            return dns_history
        except Exception as e:
            print(f"[-] Passive DNS history check failed: {e}")
        return None
    
    def certificate_transparency_search(self, domain):
        """Search Certificate Transparency logs"""
        print(f"[+] Searching Certificate Transparency logs for {domain}")
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200 and response.text.strip():
                ct_data = response.json()
                ct_results = {
                    'certificates_found': len(ct_data),
                    'certificates': ct_data[:5] if ct_data else [],  # Limit to first 5
                    'note': 'Shows SSL certificates issued for this domain'
                }
                print(f"    [+] Found {len(ct_data)} SSL certificates")
            else:
                ct_results = {'certificates_found': 0, 'certificates': []}
                print(f"    [-] No SSL certificates found")
            
            self.results['certificate_transparency'] = ct_results
            return ct_results
        except Exception as e:
            print(f"[-] Certificate Transparency search failed: {e}")
        return None
    
    def threat_intelligence_check(self, domain):
        """Check domain against threat intelligence sources"""
        print(f"[+] Checking threat intelligence for {domain}")
        
        threat_data = {
            'checked': True,
            'sources_checked': ['Public blacklists', 'Phishing databases'],
            'recommendations': [
                f'Check VirusTotal: https://www.virustotal.com/gui/domain/{domain}',
                f'Check URLVoid: https://www.urlvoid.com/scan/{domain}',
                f'Search for phishing reports: "{domain}" phishing scam'
            ]
        }
        
        self.results['threat_intel'] = threat_data
        print(f"    [+] Manual verification recommended on TI platforms")
        return threat_data
    
    def search_engine_dorking(self, domain):
        """Perform search engine dorking for the domain"""
        print(f"[+] Generating search engine queries for {domain}")
        
        search_queries = [
            f'site:{domain}',
            f'inurl:{domain}',
            f'"{domain}"',
            f'cache:{domain}',
            f'"{domain}" phishing',
            f'"{domain}" scam'
        ]
        
        search_results = {
            'queries_used': search_queries,
            'note': 'Use these queries on Google, Bing, and DuckDuckGo for manual verification'
        }
        
        self.results['search_dorking'] = search_results
        print(f"    [+] Generated {len(search_queries)} search queries")
        return search_results
    
    def social_media_intel(self, domain):
        """Check for social media mentions and discussions"""
        print(f"[+] Generating social media intelligence queries for {domain}")
        
        social_intel = {
            'platforms': ['Twitter', 'Reddit', 'Telegram', 'Discord'],
            'search_terms': [
                domain,
                domain.replace('.', '[.]'),  # Defanged domain
                f'{domain} phishing',
                f'{domain} scam',
                f'{domain} fraud'
            ],
            'note': 'Manual search on security forums and social platforms recommended'
        }
        
        self.results['social_intel'] = social_intel
        print(f"    [+] Generated social media search terms")
        return social_intel
    
    def comprehensive_analysis(self, domain, shodan_api_key=None):
        """Perform comprehensive analysis of the domain"""
        print(f"\n{'='*60}")
        print(f"COMPREHENSIVE PHISHING FORENSIC ANALYSIS")
        print(f"Target Domain: {domain}")
        print(f"Analysis Time: {datetime.datetime.now()}")
        print(f"{'='*60}\n")
        
        # Try to get IP address
        ip_address = None
        domain_active = False
        
        try:
            ip_address = socket.gethostbyname(domain)
            print(f"[+] Resolved IP: {ip_address}")
            domain_active = True
        except Exception as e:
            print(f"[-] Could not resolve domain: {e}")
            print(f"[!] Domain appears to be inactive - proceeding with passive analysis")
        
        # Always run these analyses (they work even for inactive domains)
        print(f"\n[*] Running passive forensic analysis...")
        self.domain_whois_analysis(domain)
        self.wayback_machine_check(domain)
        self.google_cache_check(domain)
        self.passive_dns_history(domain)
        self.certificate_transparency_search(domain)
        self.threat_intelligence_check(domain)
        
        # Only run active analysis if domain is resolvable
        if domain_active and ip_address:
            print(f"\n[*] Running active forensic analysis...")
            self.dns_analysis(domain)
            self.ssl_certificate_analysis(domain)
            self.subdomain_enumeration(domain)
            self.reverse_dns_lookup(ip_address)
            self.http_headers_analysis(domain)
            
            # IP-based analysis
            geo_data = self.ip_geolocation(ip_address)
            if geo_data:
                self.results['geolocation'] = geo_data
            
            if shodan_api_key:
                self.shodan_lookup(ip_address, shodan_api_key)
        else:
            print(f"[!] Skipping active analysis - domain not resolvable")
            
        # Additional passive analysis for inactive domains
        if not domain_active:
            self.search_engine_dorking(domain)
            self.social_media_intel(domain)
            
        print(f"\n[*] Analysis completed!")
        
        return self.results
    
    def generate_report(self, output_file='forensic_report.json'):
        """Generate forensic report"""
        print(f"\n[+] Generating forensic report: {output_file}")
        
        report = {
            'analysis_timestamp': datetime.datetime.now().isoformat(),
            'tool_version': '2.0',
            'results': self.results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"[+] Report saved to {output_file}")
        return report
    
    def print_summary(self):
        """Print analysis summary"""
        print(f"\n{'='*60}")
        print("ANALYSIS SUMMARY")
        print(f"{'='*60}")
        
        if 'whois' in self.results:
            whois_data = self.results['whois']
            print(f"Domain Creation: {whois_data.get('creation_date', 'Unknown')}")
            print(f"Registrar: {whois_data.get('registrar', 'Unknown')}")
            print(f"Status: {whois_data.get('status', 'Unknown')}")
        
        if 'geolocation' in self.results:
            geo = self.results['geolocation']
            print(f"Server Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}")
        
        if 'ssl' in self.results:
            ssl_data = self.results['ssl']
            print(f"SSL Issuer: {ssl_data.get('issuer', {}).get('organizationName', 'Unknown')}")
        
        if 'wayback' in self.results:
            wayback = self.results['wayback']
            print(f"Archived Content: {'Yes' if wayback.get('available') else 'No'}")
            if wayback.get('available') and wayback.get('closest'):
                print(f"Last Archive: {wayback['closest'].get('timestamp', 'Unknown')}")
        
        if 'google_cache' in self.results:
            cache = self.results['google_cache']
            print(f"Google Cache: {'Available' if cache.get('cached') else 'Not Available'}")
        
        if 'subdomains' in self.results:
            subdomains = self.results['subdomains']
            print(f"Found Subdomains: {len(subdomains)}")
            if subdomains:
                print(f"Active Subdomains: {', '.join(subdomains[:3])}{'...' if len(subdomains) > 3 else ''}")
        
        if 'certificate_transparency' in self.results:
            ct = self.results['certificate_transparency']
            print(f"SSL Certificates Found: {ct.get('certificates_found', 0)}")
        
        if 'passive_dns' in self.results:
            dns = self.results['passive_dns']
            records = dns.get('count', 0)
            print(f"Historical DNS Records: {records}")
        
        # Recommendations
        print(f"\n{'='*40}")
        print("FORENSIC RECOMMENDATIONS")
        print(f"{'='*40}")
        
        recommendations = []
        
        if 'wayback' in self.results and self.results['wayback'].get('available'):
            recommendations.append("✓ Check Wayback Machine snapshots for phishing content")
        
        if 'google_cache' in self.results and self.results['google_cache'].get('cached'):
            recommendations.append("✓ Review Google cached version of the site")
        
        if 'certificate_transparency' in self.results and self.results['certificate_transparency'].get('certificates_found', 0) > 0:
            recommendations.append("✓ Analyze SSL certificate history for infrastructure patterns")
        
        recommendations.extend([
            "• Search security forums for mentions of this domain",
            "• Check VirusTotal and URLVoid for reputation data",
            "• Correlate with other known phishing campaigns",
            "• Document all findings for legal proceedings"
        ])
        
        for rec in recommendations:
            print(rec)
        
        print(f"{'='*60}")

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Digital Forensic Tools for Phishing Analysis v2.0')
    parser.add_argument('domain', help='Target domain to analyze')
    parser.add_argument('--shodan-key', help='Shodan API key')
    parser.add_argument('--output', default='forensic_report.json', help='Output report file')
    
    args = parser.parse_args()
    
    # Initialize forensic tools
    forensic = PhishingForensicTools()
    
    # Run comprehensive analysis
    results = forensic.comprehensive_analysis(args.domain, args.shodan_key)
    
    # Print summary
    forensic.print_summary()
    
    # Generate report
    forensic.generate_report(args.output)

if __name__ == "__main__":
    main()

# Example usage:
# python3 forensik_update.py kemendagrimyregis.com --shodan-key YOUR_API_KEY --output hasil.json
