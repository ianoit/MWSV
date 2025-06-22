def scan(scanner):
    """Scan for Sensitive Data Exposure vulnerabilities"""
    print("[PLUGIN] Scanning for Sensitive Data Exposure vulnerabilities...")
    
    # Common sensitive data patterns
    sensitive_patterns = {
        'API Keys': [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
            r'api[_-]?token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
            r'access[_-]?token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?'
        ],
        'Database Credentials': [
            r'mysql[_-]?password["\']?\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*]{8,}["\']?',
            r'postgres[_-]?password["\']?\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*]{8,}["\']?',
            r'db[_-]?password["\']?\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*]{8,}["\']?',
            r'database[_-]?password["\']?\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*]{8,}["\']?'
        ],
        'Email Addresses': [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        ],
        'Phone Numbers': [
            r'[\+]?[1-9][\d]{0,15}',
            r'\(\d{3}\)\s*\d{3}-\d{4}',
            r'\d{3}-\d{3}-\d{4}'
        ],
        'Credit Card Numbers': [
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            r'\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b'
        ],
        'SSN (US)': [
            r'\b\d{3}-\d{2}-\d{4}\b',
            r'\b\d{9}\b'
        ],
        'Private Keys': [
            r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
            r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----',
            r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----'
        ],
        'AWS Keys': [
            r'AKIA[0-9A-Z]{16}',
            r'aws_access_key_id["\']?\s*[:=]\s*["\']?AKIA[0-9A-Z]{16}["\']?'
        ],
        'Google API Keys': [
            r'AIza[0-9A-Za-z\-_]{35}',
            r'google[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?AIza[0-9A-Za-z\-_]{35}["\']?'
        ],
        'GitHub Tokens': [
            r'ghp_[0-9a-zA-Z]{36}',
            r'github[_-]?token["\']?\s*[:=]\s*["\']?ghp_[0-9a-zA-Z]{36}["\']?'
        ],
        'JWT Tokens': [
            r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        ],
        'Passwords in HTML': [
            r'password["\']?\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*]{6,}["\']?',
            r'passwd["\']?\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*]{6,}["\']?'
        ]
    }
    
    # Common sensitive files and directories
    sensitive_paths = [
        '/.env',
        '/config.php',
        '/wp-config.php',
        '/config.ini',
        '/database.yml',
        '/.git/config',
        '/.svn/entries',
        '/.htaccess',
        '/robots.txt',
        '/sitemap.xml',
        '/backup/',
        '/admin/',
        '/phpinfo.php',
        '/test.php',
        '/info.php',
        '/.well-known/',
        '/api/',
        '/docs/',
        '/documentation/',
        '/logs/',
        '/tmp/',
        '/temp/',
        '/cache/',
        '/uploads/',
        '/files/',
        '/downloads/',
        '/private/',
        '/secret/',
        '/hidden/',
        '/internal/'
    ]
    
    try:
        # Scan main page for sensitive data
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout)
        response_text = response.text
        
        # Check for sensitive data patterns in response
        for data_type, patterns in sensitive_patterns.items():
            for pattern in patterns:
                matches = scanner.re.findall(pattern, response_text, scanner.re.IGNORECASE)
                if matches:
                    # Limit the number of matches to avoid overwhelming output
                    sample_matches = matches[:3]
                    scanner.log_vulnerability(
                        'Sensitive Data Exposure',
                        'High',
                        f'{data_type} found in response',
                        f'Type: {data_type}, Sample matches: {sample_matches}',
                        'CWE-200'
                    )
                    break
        
        # Check for sensitive data in HTML comments
        comment_pattern = r'<!--.*?-->'
        comments = scanner.re.findall(comment_pattern, response_text, scanner.re.DOTALL)
        
        for comment in comments:
            for data_type, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    if scanner.re.search(pattern, comment, scanner.re.IGNORECASE):
                        scanner.log_vulnerability(
                            'Sensitive Data in Comments',
                            'Medium',
                            f'{data_type} found in HTML comments',
                            f'Type: {data_type}, Comment: {comment[:100]}...',
                            'CWE-200'
                        )
                        break
        
        # Check for sensitive data in JavaScript
        script_pattern = r'<script[^>]*>.*?</script>'
        scripts = scanner.re.findall(script_pattern, response_text, scanner.re.DOTALL | scanner.re.IGNORECASE)
        
        for script in scripts:
            for data_type, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    if scanner.re.search(pattern, script, scanner.re.IGNORECASE):
                        scanner.log_vulnerability(
                            'Sensitive Data in JavaScript',
                            'High',
                            f'{data_type} found in JavaScript code',
                            f'Type: {data_type}, Script: {script[:100]}...',
                            'CWE-200'
                        )
                        break
        
        # Scan for sensitive files and directories
        for path in sensitive_paths:
            test_url = scanner.urljoin(scanner.target_url, path)
            try:
                response = scanner.session.get(test_url, timeout=scanner.timeout)
                if response.status_code == 200:
                    scanner.log_vulnerability(
                        'Sensitive File Exposure',
                        'Medium',
                        f'Sensitive file/directory accessible: {path}',
                        f'URL: {test_url}, Status: {response.status_code}',
                        'CWE-200'
                    )
            except:
                continue
        
        # Check for directory listing
        test_dirs = ['/images/', '/files/', '/uploads/', '/backup/', '/logs/', '/admin/']
        for test_dir in test_dirs:
            test_url = scanner.urljoin(scanner.target_url, test_dir)
            try:
                response = scanner.session.get(test_url, timeout=scanner.timeout)
                if response.status_code == 200:
                    # Check if it looks like directory listing
                    if '<title>' in response.text and ('Index of' in response.text or 'Directory listing' in response.text):
                        scanner.log_vulnerability(
                            'Directory Listing',
                            'Medium',
                            f'Directory listing enabled: {test_dir}',
                            f'URL: {test_url}',
                            'CWE-548'
                        )
            except:
                continue
        
        # Check for error pages that might reveal sensitive information
        error_indicators = [
            'stack trace', 'error in', 'exception', 'debug', 'warning',
            'mysql error', 'database error', 'sql error', 'php error',
            'apache error', 'nginx error', 'server error'
        ]
        
        for indicator in error_indicators:
            if indicator.lower() in response_text.lower():
                scanner.log_vulnerability(
                    'Error Information Disclosure',
                    'Low',
                    f'Error information exposed: {indicator}',
                    f'Indicator: {indicator}',
                    'CWE-209'
                )
                break
                
    except Exception as e:
        print(f"[PLUGIN][Sensitive Data Exposure] Error: {e}") 