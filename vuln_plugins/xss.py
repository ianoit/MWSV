def scan(scanner):
    """Scan for Cross-Site Scripting (XSS) vulnerabilities"""
    print("[PLUGIN] Scanning for XSS vulnerabilities...")
    xss_payloads = [
        '<script>alert("XSS")</script>',
        '\"><script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '\"><img src=x onerror=alert("XSS")>'
    ]
    try:
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            if form_action:
                test_url = scanner.urljoin(scanner.target_url, form_action)
            else:
                test_url = scanner.target_url
            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name')
                if input_name:
                    for payload in xss_payloads:
                        if form_method == 'post':
                            data = {input_name: payload}
                            try:
                                response = scanner.session.post(test_url, data=data, timeout=scanner.timeout)
                            except:
                                continue
                        else:
                            test_url_with_payload = f"{test_url}?{input_name}={scanner.urllib.parse.quote(payload)}"
                            try:
                                response = scanner.session.get(test_url_with_payload, timeout=scanner.timeout)
                            except:
                                continue
                        if payload in response.text:
                            scanner.log_vulnerability(
                                'Cross-Site Scripting (XSS)',
                                'High',
                                f'XSS vulnerability detected in parameter {input_name}',
                                f'Payload: {payload}',
                                'CWE-79'
                            )
                            break
    except Exception as e:
        print(f"[PLUGIN][XSS] Error: {e}") 