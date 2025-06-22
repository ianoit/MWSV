def scan(scanner):
    """Scan for Security Headers vulnerabilities"""
    print("[PLUGIN] Scanning for Security Headers vulnerabilities...")
    
    try:
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout)
        headers = response.headers
        
        # Check for missing security headers
        security_headers = {
            'Strict-Transport-Security': {
                'description': 'Missing HSTS header',
                'severity': 'Medium',
                'cwe': 'CWE-319',
                'recommendation': 'Add Strict-Transport-Security header to enforce HTTPS'
            },
            'Content-Security-Policy': {
                'description': 'Missing CSP header',
                'severity': 'Medium',
                'cwe': 'CWE-693',
                'recommendation': 'Add Content-Security-Policy header to prevent XSS'
            },
            'X-Frame-Options': {
                'description': 'Missing X-Frame-Options header',
                'severity': 'Medium',
                'cwe': 'CWE-1021',
                'recommendation': 'Add X-Frame-Options header to prevent clickjacking'
            },
            'X-Content-Type-Options': {
                'description': 'Missing X-Content-Type-Options header',
                'severity': 'Low',
                'cwe': 'CWE-434',
                'recommendation': 'Add X-Content-Type-Options: nosniff header'
            },
            'X-XSS-Protection': {
                'description': 'Missing X-XSS-Protection header',
                'severity': 'Low',
                'cwe': 'CWE-79',
                'recommendation': 'Add X-XSS-Protection header (though deprecated, still useful)'
            },
            'Referrer-Policy': {
                'description': 'Missing Referrer-Policy header',
                'severity': 'Low',
                'cwe': 'CWE-116',
                'recommendation': 'Add Referrer-Policy header to control referrer information'
            },
            'Permissions-Policy': {
                'description': 'Missing Permissions-Policy header',
                'severity': 'Low',
                'cwe': 'CWE-1021',
                'recommendation': 'Add Permissions-Policy header to control browser features'
            }
        }
        
        missing_headers = []
        
        for header, info in security_headers.items():
            if header not in headers:
                missing_headers.append((header, info))
                scanner.log_vulnerability(
                    'Missing Security Header',
                    info['severity'],
                    info['description'],
                    f'Header: {header}, Recommendation: {info["recommendation"]}',
                    info['cwe']
                )
        
        # Check for weak security header values
        if 'X-Frame-Options' in headers:
            xfo_value = headers['X-Frame-Options']
            if xfo_value.lower() not in ['deny', 'sameorigin']:
                scanner.log_vulnerability(
                    'Weak X-Frame-Options',
                    'Medium',
                    'X-Frame-Options header has weak value',
                    f'Current value: {xfo_value}, Should be: DENY or SAMEORIGIN',
                    'CWE-1021'
                )
        
        if 'X-Content-Type-Options' in headers:
            xcto_value = headers['X-Content-Type-Options']
            if xcto_value.lower() != 'nosniff':
                scanner.log_vulnerability(
                    'Weak X-Content-Type-Options',
                    'Low',
                    'X-Content-Type-Options header has weak value',
                    f'Current value: {xcto_value}, Should be: nosniff',
                    'CWE-434'
                )
        
        if 'X-XSS-Protection' in headers:
            xxp_value = headers['X-XSS-Protection']
            if '1; mode=block' not in xxp_value.lower():
                scanner.log_vulnerability(
                    'Weak X-XSS-Protection',
                    'Low',
                    'X-XSS-Protection header has weak value',
                    f'Current value: {xxp_value}, Should be: 1; mode=block',
                    'CWE-79'
                )
        
        # Check for information disclosure headers
        info_disclosure_headers = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Runtime',
            'X-Version',
            'X-Generator'
        ]
        
        for header in info_disclosure_headers:
            if header in headers:
                scanner.log_vulnerability(
                    'Information Disclosure',
                    'Low',
                    f'Sensitive header {header} is exposed',
                    f'Header: {header}, Value: {headers[header]}',
                    'CWE-200'
                )
        
        # Summary
        if missing_headers:
            print(f"[PLUGIN][Security Headers] Found {len(missing_headers)} missing security headers")
        else:
            print("[PLUGIN][Security Headers] All critical security headers are present")
            
    except Exception as e:
        print(f"[PLUGIN][Security Headers] Error: {e}") 