def scan(scanner):
    """Scan for CSRF vulnerabilities"""
    print("[PLUGIN] Scanning for CSRF vulnerabilities...")
    try:
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            form_method = form.get('method', 'get').lower()
            if form_method == 'post':
                csrf_tokens = form.find_all('input', {'name': scanner.re.compile(r'csrf|token|nonce', scanner.re.I)})
                if not csrf_tokens:
                    scanner.log_vulnerability(
                        'Cross-Site Request Forgery (CSRF)',
                        'High',
                        'Form lacks CSRF protection token',
                        f'Form method: {form_method}',
                        'CWE-352'
                    )
                else:
                    print("[PLUGIN][CSRF] CSRF token found in form")
    except Exception as e:
        print(f"[PLUGIN][CSRF] Error: {e}") 