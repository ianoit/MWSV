def scan(scanner):
    """Scan for Insecure Direct Object References (IDOR) vulnerabilities"""
    print("[PLUGIN] Scanning for IDOR vulnerabilities...")
    
    # Common IDOR parameters and patterns
    idor_patterns = [
        # User IDs
        r'user[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'uid["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        
        # Order IDs
        r'order[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'order["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        
        # Document IDs
        r'doc[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'document[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'file[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        
        # Account IDs
        r'account[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'acct[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        
        # Profile IDs
        r'profile[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'profile["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        
        # Message IDs
        r'message[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'msg[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        
        # Post IDs
        r'post[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'post["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        
        # Comment IDs
        r'comment[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'comment["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        
        # Product IDs
        r'product[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'prod[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        
        # Category IDs
        r'category[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?',
        r'cat[_-]?id["\']?\s*[:=]\s*["\']?(\d+)["\']?'
    ]
    
    # Common IDOR endpoints
    idor_endpoints = [
        '/user/',
        '/users/',
        '/profile/',
        '/account/',
        '/order/',
        '/orders/',
        '/document/',
        '/documents/',
        '/file/',
        '/files/',
        '/message/',
        '/messages/',
        '/post/',
        '/posts/',
        '/comment/',
        '/comments/',
        '/product/',
        '/products/',
        '/category/',
        '/categories/',
        '/admin/user/',
        '/admin/order/',
        '/api/user/',
        '/api/order/',
        '/api/profile/',
        '/api/document/'
    ]
    
    try:
        # Scan main page for IDOR patterns
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout)
        response_text = response.text
        
        # Look for IDOR patterns in the response
        for pattern in idor_patterns:
            matches = scanner.re.findall(pattern, response_text, scanner.re.IGNORECASE)
            if matches:
                # Test for IDOR by trying different IDs
                for match in matches[:3]:  # Limit to first 3 matches
                    try:
                        # Test with different ID values
                        test_ids = [str(int(match) + 1), str(int(match) - 1), str(int(match) + 10)]
                        
                        for test_id in test_ids:
                            # Replace the ID in the pattern
                            test_pattern = pattern.replace(r'(\d+)', test_id)
                            test_url = scanner.target_url.replace(match, test_id)
                            
                            try:
                                test_response = scanner.session.get(test_url, timeout=scanner.timeout)
                                if test_response.status_code == 200 and test_response.text != response_text:
                                    scanner.log_vulnerability(
                                        'Insecure Direct Object Reference (IDOR)',
                                        'High',
                                        f'IDOR vulnerability detected with ID parameter',
                                        f'Original ID: {match}, Test ID: {test_id}, Pattern: {pattern}',
                                        'CWE-639'
                                    )
                                    break
                            except:
                                continue
                    except ValueError:
                        continue
        
        # Test common IDOR endpoints
        for endpoint in idor_endpoints:
            # Test with different user IDs
            test_ids = ['1', '2', '3', '10', '100', '1000']
            
            for test_id in test_ids:
                test_url = scanner.urljoin(scanner.target_url, f"{endpoint}{test_id}")
                
                try:
                    response = scanner.session.get(test_url, timeout=scanner.timeout)
                    if response.status_code == 200:
                        # Check if response contains user-specific information
                        user_indicators = [
                            'user', 'profile', 'account', 'email', 'phone', 'address',
                            'name', 'username', 'login', 'password', 'credit', 'card',
                            'order', 'purchase', 'history', 'balance', 'account'
                        ]
                        
                        response_text = response.text.lower()
                        for indicator in user_indicators:
                            if indicator in response_text:
                                scanner.log_vulnerability(
                                    'Potential IDOR',
                                    'Medium',
                                    f'Potential IDOR vulnerability in endpoint: {endpoint}{test_id}',
                                    f'URL: {test_url}, Contains: {indicator}',
                                    'CWE-639'
                                )
                                break
                except:
                    continue
        
        # Test for horizontal privilege escalation
        # Look for user-specific data in forms or links
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Check forms for user ID parameters
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                input_value = input_field.get('value', '')
                
                # Check if input contains user ID
                if any(keyword in input_name for keyword in ['user', 'id', 'uid', 'account']):
                    if input_value and input_value.isdigit():
                        # Test with different user ID
                        test_id = str(int(input_value) + 1)
                        form_action = form.get('action', '')
                        form_method = form.get('method', 'post').lower()
                        
                        if form_action:
                            test_url = scanner.urljoin(scanner.target_url, form_action)
                        else:
                            test_url = scanner.target_url
                        
                        # Create test data
                        test_data = {}
                        for inp in inputs:
                            inp_name = inp.get('name')
                            inp_value = inp.get('value', '')
                            if inp_name == input_name:
                                test_data[inp_name] = test_id
                            elif inp_name:
                                test_data[inp_name] = inp_value
                        
                        if test_data:
                            try:
                                if form_method == 'post':
                                    test_response = scanner.session.post(test_url, data=test_data, timeout=scanner.timeout)
                                else:
                                    test_response = scanner.session.get(test_url, params=test_data, timeout=scanner.timeout)
                                
                                if test_response.status_code == 200:
                                    scanner.log_vulnerability(
                                        'Form-based IDOR',
                                        'High',
                                        f'IDOR vulnerability in form with parameter {input_name}',
                                        f'Original value: {input_value}, Test value: {test_id}',
                                        'CWE-639'
                                    )
                            except:
                                continue
        
        # Check for IDOR in URL parameters
        parsed_url = scanner.urllib.parse.urlparse(scanner.target_url)
        query_params = scanner.urllib.parse.parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            if any(keyword in param.lower() for keyword in ['user', 'id', 'uid', 'account', 'order', 'doc']):
                if values and values[0].isdigit():
                    original_value = values[0]
                    test_value = str(int(original_value) + 1)
                    
                    # Create test URL
                    test_params = query_params.copy()
                    test_params[param] = [test_value]
                    test_query = scanner.urllib.parse.urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"
                    
                    try:
                        test_response = scanner.session.get(test_url, timeout=scanner.timeout)
                        if test_response.status_code == 200 and test_response.text != response.text:
                            scanner.log_vulnerability(
                                'URL Parameter IDOR',
                                'High',
                                f'IDOR vulnerability in URL parameter {param}',
                                f'Original value: {original_value}, Test value: {test_value}',
                                'CWE-639'
                            )
                    except:
                        continue
                        
    except Exception as e:
        print(f"[PLUGIN][IDOR] Error: {e}") 