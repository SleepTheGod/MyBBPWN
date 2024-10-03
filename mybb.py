import requests
from prettytable import PrettyTable

def get_http_response(url):
    """Send an HTTP GET request to the specified URL and return the response."""
    try:
        response = requests.get(url)
        return response
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def parse_response(response):
    """Parse the HTTP response and display relevant information."""
    
    # Display HTTP headers
    print("---- HTTP Headers ----")
    headers_table = PrettyTable()
    headers_table.field_names = ["Header", "Value"]

    for header, value in response.headers.items():
        headers_table.add_row([header, value])

    print(headers_table)
    print("----------------------\n")

    # Display MyBB-specific cookies
    print("---- MyBB Cookies ----")
    mybb_cookies = ['mybb[lastvisit]', 'mybb[lastactive]', 'sid', 'adminsid', 'loginattempts']
    cookies_table = PrettyTable()
    cookies_table.field_names = ["Cookie Name", "Value"]

    for cookie in response.cookies:
        if cookie.name in mybb_cookies:
            cookies_table.add_row([cookie.name, cookie.value])

    print(cookies_table)
    print("----------------------\n")

    # Security recommendations
    print("---- Security Recommendations ----")
    vulnerabilities = []

    if 'Server' in response.headers:
        server = response.headers['Server']
        if "cloudflare" in server.lower():
            vulnerabilities.append("- Server detected: Cloudflare. Ensure it is secured.")
        if "Apache" in server:
            vulnerabilities.append("- Apache web server detected. Check for outdated modules.")
        
        if "MyBB" in response.text:
            vulnerabilities.append("- MyBB forum detected. Ensure it's updated to the latest version.")
    
    if len(vulnerabilities) == 0:
        print("No specific vulnerabilities detected.")
    else:
        for vulnerability in vulnerabilities:
            print(vulnerability)

    print("---------------------------------------\n")

def main():
    """Main function to run the script."""
    # Prompt user for domain
    target_domain = input("Enter the MyBB forum URL (e.g., https://forum.example.com): ")
    
    # Normalize the URL
    if not target_domain.startswith("http://") and not target_domain.startswith("https://"):
        target_domain = "https://" + target_domain

    response = get_http_response(target_domain)

    if response:
        parse_response(response)

if __name__ == "__main__":
    main()
