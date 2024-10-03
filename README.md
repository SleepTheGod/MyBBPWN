# MyBBPWN TOOLKIT


How to install this.

```bash
git clone https://github.com/SleepTheGod/MyBBPWN/
cd MyBBPWN
chmod +x main.py
pip install prettytable
python main.py
```

Overview
The following Python script is designed to interact with MyBB (My Bulletin Board) forums by sending HTTP GET requests to specified URLs and analyzing the responses. It aims to provide security insights related to HTTP headers, cookies, and potential vulnerabilities associated with the MyBB software and the server hosting it.

Dependencies

The script uses the requests library for sending HTTP requests and prettytable for formatting output in a readable table format.

Function get_http_response(url)

This function sends a GET request to the specified URL.
It handles exceptions to gracefully manage any issues that arise during the request (e.g., network errors).
Returns the HTTP response object or None in case of an error.
Function: parse_response(response)

This function analyzes the HTTP response and provides several key outputs
HTTP Headers Displays all HTTP headers returned by the server using PrettyTable, allowing for quick identification of server characteristics and configurations.
MyBB Cookies It specifically looks for MyBB-related cookies to assess session management and user activity tracking, presenting these in a formatted table.
Security Recommendations: Evaluates the HTTP response for potential vulnerabilities based on server information and the presence of MyBB. Key checks include:
Server type detection (e.g., Apache, Cloudflare) to identify misconfigurations or outdated software.
Confirmation of MyBB software presence to recommend updates, which is crucial for security patches.
Function: main()

Prompts the user for the target MyBB forum URL.
Normalizes the input to ensure it starts with "http://" or "https://".
Calls get_http_response() and subsequently parse_response() if a valid response is received.
Security Implications
This script serves as a preliminary security assessment tool for MyBB forums. Its outputs can guide administrators in:

Identifying Potential Risks By checking for outdated server software or misconfigurations that could be exploited by attackers.
Enhancing Security Posture The recommendations provided can help in implementing necessary updates and configurations to secure the forum.
Session Management Awareness Analyzing cookies associated with MyBB can shed light on how user sessions are managed and the potential risks of session hijacking or fixation.
