# Test Results

Python version used: 3.12.6 | Operating system: Windows 11 | Date: 2026-10-28

| # | Input | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|
| 1 | `https://www.example.com/login` | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | `http://192.0.2.10/account` | IP address + HTTP | Uses an IP address instead of a familiar domain.; Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 3 | `http://example.com@sample.invalid/login` | @ symbol + HTTP | Contains an @ symbol; inspect carefully.; Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Many hostname segments | Contains many hostname segments/subdomains. | PASS |
| 5 | `https://xn--example.invalid/` | Punycode-style hostname | Contains a punycode-style hostname. | PASS |

## Notes

What I learned: A defensive security tool can analyze URL structure, flags, and anomalies (such as punycode, raw IP addresses, and @ signs) completely offline without sending network requests or risking malware.  
What surprised me: A URL with zero warnings is never guaranteed to be safe—clever attackers can register authentic-looking domains that pass static syntax tests. HTTPS alone does not prove a site is honest.
