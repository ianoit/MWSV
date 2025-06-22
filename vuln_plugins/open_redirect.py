def scan(scanner):
    """Scan for Open Redirect vulnerabilities"""
    print("[PLUGIN] Scanning for Open Redirect vulnerabilities...")
    redirect_payloads = [
        'http://evil.com',
        'https://attacker.com',
        '//evil.com',
        'javascript:alert("redirect")'
    ]
    redirect_params = ['redirect', 'url', 'next', 'target', 'redir', 'destination']
    try:
        for param in redirect_params:
            for payload in redirect_payloads:
                test_url = f"{scanner.target_url}?{param}={scanner.urllib.parse.quote(payload)}"
                try:
                    response = scanner.session.get(test_url, timeout=scanner.timeout, allow_redirects=False)
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if payload in location or 'evil.com' in location or 'attacker.com' in location:
                            scanner.log_vulnerability(
                                'Open Redirect',
                                'Medium',
                                f'Open redirect vulnerability in parameter {param}',
                                f'Redirects to: {location}',
                                'CWE-601'
                            )
                            break
                except Exception as e:
                    continue
    except Exception as e:
        print(f"[PLUGIN][Open Redirect] Error: {e}") 