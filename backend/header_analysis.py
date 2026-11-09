import re
import ipaddress

ADDRESS_HEADERS = (
    "from",
    "to",
    "cc",
    "reply-to",
    "return-path",
)

# Check headers in list, finds email addresses within the raw header values
def extract_header_emails(header_map: dict) -> list[str]:
    """Extract email addresses from selected email headers."""
    emails = []

    for header in ADDRESS_HEADERS:
        value = header_map.get(header, "")
        matches = re.findall(
            r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+",
            value
        )
        emails.extend(matches)

    return list(dict.fromkeys(email.lower() for email in emails))

# Extract domains from email addresses 
def extract_header_domains(header_map: dict) -> list[str]:
    """Extract unique domains from email addresses in selected headers."""
    emails = extract_header_emails(header_map)

    domains = [
        email.split("@")[-1]
        for email in emails
    ]

    return list(dict.fromkeys(domains))

# Extract ip addresses (IPV4 handeling)
def extract_header_ips(received_headers: list[str]) -> list[str]:
    """Extract unique IP addresses from Received headers."""
    ips = []

    for header in received_headers:
        matches = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            header
        )

        for match in matches:
            try:
                ipaddress.ip_address(match)
                ips.append(match)
            except ValueError:
                continue

    return list(dict.fromkeys(ips))

# Email, domain, ip call
def analyze_headers(header_map: dict, received_headers: list[str]) -> dict:
    """Extract email addresses, domains, and IPs from email headers."""
    return {
        "emails": extract_header_emails(header_map),
        "domains": extract_header_domains(header_map),
        "ips": extract_header_ips(received_headers)
    }