def scan(scanner):
    """Scan for Directory Traversal vulnerabilities"""
    print("[PLUGIN] Scanning for Directory Traversal vulnerabilities...")
    traversal_payloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
    ]
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(scanner.target_url)
        base_path = parsed_url.path
        for payload in traversal_payloads:
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{base_path}/{payload}"
            try:
                response = scanner.session.get(test_url, timeout=scanner.timeout)
                if 'root:x:' in response.text or 'bin:x:' in response.text:
                    scanner.log_vulnerability(
                        'Directory Traversal',
                        'High',
                        'Directory traversal vulnerability detected',
                        f'Payload: {payload}',
                        'CWE-22'
                    )
                    break
            except Exception as e:
                continue
    except Exception as e:
        print(f"[PLUGIN][Directory Traversal] Error: {e}") 