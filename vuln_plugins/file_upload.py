def scan(scanner):
    """Scan for Insecure File Upload vulnerabilities"""
    print("[PLUGIN] Scanning for File Upload vulnerabilities...")
    
    try:
        from bs4 import BeautifulSoup
        import io
        # Cari form upload file
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout)
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            has_file = False
            for input_field in form.find_all('input'):
                if input_field.get('type', '').lower() == 'file':
                    has_file = True
                    break
            if not has_file:
                continue
            form_action = form.get('action', '')
            form_method = form.get('method', 'post').lower()
            if form_action:
                test_url = scanner.urljoin(scanner.target_url, form_action)
            else:
                test_url = scanner.target_url
            # Coba upload file berbahaya
            test_files = [
                ('shell.php', b'<?php echo "vuln"; ?>'),
                ('shell.asp', b'<% Response.Write("vuln") %>'),
                ('shell.jsp', b'<% out.println("vuln"); %>'),
                ('shell.png', b'\x89PNG\r\n\x1a\n'),
            ]
            for fname, fcontent in test_files:
                files = {}
                for input_field in form.find_all('input'):
                    if input_field.get('type', '').lower() == 'file':
                        files[input_field.get('name')] = (fname, io.BytesIO(fcontent))
                data = {}
                for input_field in form.find_all('input'):
                    if input_field.get('type', '').lower() not in ['file', 'submit']:
                        data[input_field.get('name')] = input_field.get('value', 'test')
                try:
                    if form_method == 'post':
                        upload_response = scanner.session.post(test_url, data=data, files=files, timeout=scanner.timeout)
                    else:
                        upload_response = scanner.session.get(test_url, params=data, files=files, timeout=scanner.timeout)
                except Exception as e:
                    continue
                # Cek response upload
                if upload_response.status_code in [200, 201, 202, 204, 302, 301]:
                    # Coba akses file yang diupload jika ada petunjuk nama file di response
                    for fname in files.values():
                        if fname[0] in upload_response.text:
                            scanner.log_vulnerability(
                                'Insecure File Upload',
                                'Critical',
                                f'File {fname[0]} uploaded and referenced in response',
                                f'File: {fname[0]}',
                                'CWE-434'
                            )
                            break
                # Cek response mengandung error upload
                if 'file type not allowed' in upload_response.text.lower() or 'invalid file' in upload_response.text.lower():
                    continue
                # Jika response mengandung nama file upload
                for fname in files.values():
                    if fname[0] in upload_response.text:
                        scanner.log_vulnerability(
                            'Potential Insecure File Upload',
                            'High',
                            f'File {fname[0]} appears in upload response',
                            f'File: {fname[0]}',
                            'CWE-434'
                        )
                        break
    except Exception as e:
        print(f"[PLUGIN][File Upload] Error: {e}") 