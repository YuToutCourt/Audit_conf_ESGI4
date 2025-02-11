import re

def check_autoindex(config):
    if re.search(r"\bautoindex\s+on\b", config):
        return "Warning: Directory listing (autoindex) is enabled, which can expose files."
    return None

def check_server_tokens(config):
    if not re.search(r"\bserver_tokens\s+off\b", config):
        return "Warning: 'server_tokens off;' is missing. It is recommended to hide the NGINX version."
    return None

def check_ssl_protocols(config):
    weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
    match = re.search(r"\bssl_protocols\s+([^;]+);", config)
    if match:
        protocols = match.group(1).strip().split()
        for protocol in protocols:
            if protocol in weak_protocols:
                return f"Warning: Weak SSL protocol found: {protocol}. It is recommended to use TLS 1.2 or higher."
    else:
        return "Warning: 'ssl_protocols' not configured. Specify SSL protocols to avoid default settings."
    return None

def check_ssl_ciphers(config):
    weak_ciphers = ["RC4", "DES", "MD5"]
    match = re.search(r"\bssl_ciphers\s+([^;]+);", config)
    if match:
        ciphers = match.group(1).strip().split(":")
        for cipher in ciphers:
            for weak_cipher in weak_ciphers:
                if weak_cipher in cipher:
                    return f"Warning: Weak SSL cipher found: {cipher}. Consider using stronger cipher suites."
    else:
        return "Warning: 'ssl_ciphers' not configured. Specify SSL ciphers to avoid weak default settings."
    return None

def check_client_max_body_size(config):
    match = re.search(r"\bclient_max_body_size\s+([^;]+);", config)
    if match:
        size = match.group(1).strip()
        return f"Notice: 'client_max_body_size' set to {size}. Verify that this is appropriate for your server."
    return None

def check_http_redirect(config):
    if not re.search(r"return\s+301\s+https://\$host\$request_uri;", config):
        return "Warning: HTTP to HTTPS redirection is missing. Redirect HTTP traffic to HTTPS for better security."
    return None

def check_x_frame_options(config):
    if not re.search(r"add_header\s+X-Frame-Options", config):
        return "Warning: 'X-Frame-Options' header is missing. Add it to prevent clickjacking attacks."
    return None

def check_x_content_type_options(config):
    if not re.search(r"add_header\s+X-Content-Type-Options", config):
        return "Warning: 'X-Content-Type-Options' header is missing. Add it to prevent MIME-sniffing attacks."
    return None

def check_content_security_policy(config):
    if not re.search(r"add_header\s+Content-Security-Policy", config):
        return "Warning: 'Content-Security-Policy' header is missing. Add it to mitigate XSS attacks."
    return None

def analyze_nginx_conf(file_path):
    with open(file_path, 'r') as file:
        config = file.read()

def check_valid_referers_is_not_none(config):
    if not re.search(r"valid_referers none blocked server_names", config):
        return "Warning: 'valid_referers' is not set to 'none blocked server_names'."

def check_alias_traversal(config):
    alias_patterns = re.findall(r"location\s+(.*?)\s*\{\s*alias\s+(.*?);", config, re.DOTALL)
    for location, alias_path in alias_patterns:
        # Check if the location path does not end with '/' and the alias path does not end with '/'
        if not location.endswith('/') and not alias_path.endswith('/'):
            return (
                "Warning: Path traversal vulnerability detected in alias configuration.\n"
                "Using alias in a prefixed location that doesn't end with a directory separator could lead "
                "to a path traversal vulnerability.\n"
                "Help URL: https://github.com/yandex/gixy/blob/master/docs/en/plugins/aliastraversal.md"
            )
    return None

def check_host_spoofing(config):
    if re.search(r"host", config):
        if re.search(r"proxy_set_header\s+Host", config):
            return "Warning: Host header spoofing detected. Ensure that the Host header is not set from user input."
    return None

def check_http_splitting(config):

    # Patterns to match directives that may be vulnerable to HTTP splitting
    vulnerable_directives = [
        r"rewrite\s+.+\s+http://\$host\$uri",
        r"return\s+301\s+http://\$host\$uri",
        r"proxy_set_header\s+\"X-Original-Uri\"\s+\$uri",
        r"proxy_pass\s+http://[^;]+",
        r"location\s+~\s+/proxy/.*\{\s+set\s+\$path\s+\$\w+;\s+proxy_pass\s+http://[^;]+"
    ]
    
    # Check each pattern for potential vulnerabilities
    for pattern in vulnerable_directives:
        if re.search(pattern, config, re.DOTALL):
            return (
                "Warning: Possible HTTP Splitting vulnerability detected.\n"
                "Using variables that may contain '\\n' or '\\r' in directives like 'rewrite', 'return', "
                "'add_header', 'proxy_set_header', or 'proxy_pass' can lead to HTTP injection.\n" 
            )
    return None

def check_ssrf(config):
    # Patterns to detect risky `proxy_pass` configurations with variables in the URL scheme, host, or path
    ssrf_patterns = [
        r"location\s+~\s+/proxy/\(.*?\)\s*\{[^}]*?proxy_pass\s+\$[a-zA-Z]+://\$[a-zA-Z]+/\$[a-zA-Z]+;",
        r"location\s+/proxy/\s*\{\s*proxy_pass\s+\$arg_[a-zA-Z]+;"
    ]
    
    # Check each pattern to see if any risky configurations are present
    for pattern in ssrf_patterns:
        if re.search(pattern, config, re.DOTALL):
            return (
                "Warning: Possible SSRF (Server-Side Request Forgery) vulnerability detected.\n"
                "The configuration may allow an attacker to create arbitrary requests from the vulnerable server.\n"
            )
    return None

def check_add_header_redefinition(config):
    server_blocks = re.findall(r"server\s*{([^}]+)}", config, re.DOTALL)
    
    for server_block in server_blocks:
        # Find headers in the server block
        server_headers = set(re.findall(r"add_header\s+([^\s]+)\s+[^;]+;", server_block, re.IGNORECASE))
        
        # Look for nested location or if blocks within the server block
        nested_blocks = re.findall(r"(location\s+/.*?{|if\s+[^}]*{)([^}]+)}", server_block, re.DOTALL)
        
        for _, nested_block_content in nested_blocks:
            nested_headers = set(re.findall(r"add_header\s+([^\s]+)\s+[^;]+;", nested_block_content, re.IGNORECASE))
            
            # Check if nested headers redefine headers from the server block
            overridden_headers = server_headers & nested_headers
            if overridden_headers:
                return (
                    f"Warning: Nested 'add_header' directive detected, which may replace parent headers: "
                    f"{', '.join(overridden_headers)}.\n"
                    "Using 'add_header' in a nested context replaces all headers from the parent level.\n"
                )
    return None

def check_add_header_multiline(config):
    # Match any multi-line 'add_header' or 'more_set_headers' directive that uses line breaks or tabs
    multiline_header_pattern = re.compile(
        r"(add_header|more_set_headers)\s+[^;]*?\n\s+",
        re.MULTILINE
    )
    
    if multiline_header_pattern.search(config):
        return (
            "Warning: Multi-line 'add_header' directive detected. Multi-line headers are deprecated (RFC 7230), "
            "and some clients (e.g., Internet Explorer and Edge) may not support them.\n"
        )
    return None
    
def main():
    # Run each check function and collect any warnings or notices
    config = analyze_nginx_conf("path/to/your/nginx.conf")
    
    report = []
    checks = [
        check_autoindex,
        check_server_tokens,
        check_ssl_protocols,
        check_ssl_ciphers,
        check_client_max_body_size,
        check_http_redirect,
        check_x_frame_options,
        check_x_content_type_options,
        check_content_security_policy,
        check_valid_referers_is_not_none,
        check_alias_traversal,
        check_host_spoofing,        
    ]
    
    for check in checks:
        result = check(config)
        if result:
            report.append(result)

    # Report the findings
    if report:
        print("NGINX Configuration Analysis Report:")
        for item in report:
            print(f"- {item}")
    else:
        print("No issues found. The configuration appears secure.")

# Usage: analyze_nginx_conf("path/to/your/nginx.conf")
