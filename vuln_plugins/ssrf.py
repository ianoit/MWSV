def scan(scanner):
    """Scan for Server-Side Request Forgery (SSRF) vulnerabilities"""
    print("[PLUGIN] Scanning for SSRF vulnerabilities...")
    ssrf_payloads = [
        'http://127.0.0.1:22',
        'http://localhost:3306',
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/passwd'
    ]
    ssrf_params = ['url', 'uri', 'path', 'src', 'dest', 'redirect', 'redirect_uri', 'callback', 'return', 'next']
    try:
        for param in ssrf_params:
            for payload in ssrf_payloads:
                test_url = f"{scanner.target_url}?{param}={scanner.urllib.parse.quote(payload)}"
                try:
                    response = scanner.session.get(test_url, timeout=scanner.timeout)
                    ssrf_indicators = [
                        'ssh-rsa', 'mysql', 'redis', 'memcached', 'amazonaws',
                        'internal server error', 'connection refused', 'timeout'
                    ]
                    response_text = response.text.lower()
                    for indicator in ssrf_indicators:
                        if indicator in response_text:
                            scanner.log_vulnerability(
                                'Server-Side Request Forgery (SSRF)',
                                'High',
                                f'SSRF vulnerability detected in parameter {param}',
                                f'Payload: {payload}, Indicator: {indicator}',
                                'CWE-918'
                            )
                            break
                except Exception as e:
                    continue
    except Exception as e:
        print(f"[PLUGIN][SSRF] Error: {e}") 