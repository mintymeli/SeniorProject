
import base64
import httpx
import time
from urllib.parse import quote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from config import VIRUSTOTAL_API_KEY
from config import IPQS_API_KEY
from config import URLSCAN_API_KEY
from config import URLHAUS_API_KEY


# ----- VirusTotal Analysis -----

# VT API settings
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 20

# Creates the headers needed to authenticate with VT
def _get_headers():

    return {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

# Extracts the number of malicious, suspicious, harmless, and undetected results
def _get_detection_counts(attributes):
    """Extract VirusTotal detection counts."""
    stats = attributes.get("last_analysis_stats", {})

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }

# Handles errors returned by VT when a report cannot be retrieved
def _handle_error(response, indicator):
    """Return a readable error for an unsuccessful VT request."""
    if response.status_code == 404:
        return {
            "status": "No report found",
            "indicator": indicator
        }

    if response.status_code == 429:
        return {
            "status": "Rate limited",
            "indicator": indicator,
            "error": "VirusTotal API rate limit reached."
        }

    return {
        "status": "Error",
        "indicator": indicator,
        "error": f"VirusTotal returned HTTP {response.status_code}."
    }

# ----- VirusTotal URL Analysis -----

# Looks up a VT report for links
def analyze_url_virustotal(url):

    if not VIRUSTOTAL_API_KEY:
        return {
            "url": url,
            "status": "Error",
            "error": "VirusTotal API key is not configured."
        }

    # Converts the URL into the format VT uses to identify links
    url_id = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    # Requests the URL's existing VT report
    try:
        response = httpx.get(
            endpoint,
            headers=_get_headers(),
            timeout=VT_TIMEOUT
        )

        # Handles the reponse if the report cannot be retrieved
        if response.status_code != 200:
            result = _handle_error(response, url)
            result["url"] = url
            return result

        # Extracts the analysis information from the report
        attributes = response.json()["data"]["attributes"]

        return {
            "url": url,
            "status": "Report found",
            **_get_detection_counts(attributes)
        }

    # Handles connection problems with VT
    except httpx.RequestError:
        return {
            "url": url,
            "status": "Error",
            "error": "Could not connect to VirusTotal."
        }

    # Handles unexpected or invalid response data
    except (ValueError, KeyError, TypeError):
        return {
            "url": url,
            "status": "Error",
            "error": "Could not read the VirusTotal response."
        }

# ----- VT Hash Analysis -----

# Looks up hash in VT
def analyze_hash_virustotal(file_hash):

    if not VIRUSTOTAL_API_KEY:
        return {
            "sha256": file_hash,
            "status": "Error",
            "error": "VirusTotal API key is not configured."
        }

    # Uses the file hash to request the hash output report
    endpoint = f"{VT_BASE_URL}/files/{file_hash}"

    try:
        response = httpx.get(
            endpoint,
            headers=_get_headers(),
            timeout=VT_TIMEOUT
        )

        # Handles the reponse if the report cannot be retrived
        if response.status_code != 200:
            result = _handle_error(response, file_hash)
            result["sha256"] = file_hash
            return result

        # Extracts the analysis information from the report
        attributes = response.json()["data"]["attributes"]

        return {
            "sha256": file_hash,
            "status": "Report found",
            **_get_detection_counts(attributes)
        }

    # Handles connection problems with VT
    except httpx.RequestError:
        return {
            "sha256": file_hash,
            "status": "Error",
            "error": "Could not connect to VirusTotal."
        }

    # Handles unexpected or invalud reponse data
    except (ValueError, KeyError, TypeError):
        return {
            "sha256": file_hash,
            "status": "Error",
            "error": "Could not read the VirusTotal response."
        }

# ----- IPQualityScore URL Analysis -----

# Checks a URL using IPQS
def analyze_url_ipqs(url):

    # Check if the IPQS key is not configured
    if not IPQS_API_KEY:
        return {
            "url": url,
            "status": "Error",
            "error": "IPQS API key is not configured."
        }

    # Encode the URL so it can be sent to the IPQS API
    encoded_url = quote(url, safe="")

    # IPQS API address for checking URLs
    endpoint = (
        f"https://www.ipqualityscore.com/api/json/url/"
        f"{IPQS_API_KEY}/{encoded_url}"
    )

    # Sends the API request
    try:
        response = httpx.get(endpoint, timeout=20)

        # Handle HTTP errors
        if response.status_code != 200:
            return {
                "url": url,
                "status": "Error",
                "error": f"IPQS returned HTTP {response.status_code}."
            }

        data = response.json()

        # Check if IPQS reported an error with the analysis
        if data.get("success") is False:
            return {
                "url": url,
                "status": "Error",
                "error": data.get(
                    "message",
                    "IPQS could not analyze this URL."
                )
            }

        # Returns URL's safety status and domain age from the results
        unsafe = data.get("unsafe")
        domain_age = data.get("domain_age")

        # Convert domain age to readable text
        if isinstance(domain_age, dict):
            domain_age = domain_age.get("human", "N/A")

        # Returns the URL and security information to be displayed
        return {
            "url": url,
            "status": "Report found",
            "safe": not unsafe if isinstance(unsafe, bool) else "Not found",
            "suspicious": data.get("suspicious", "Not found"),
            "domain": data.get("domain") or "Not found",
            "malware": data.get("malware", "Not found"),
            "phishing": data.get("phishing", "Not found"),
            "risk_score": data.get("risk_score", "Not found"),
            "domain_age": domain_age or "Not found"
        }

    # Handles connection problems
    except httpx.RequestError:
        return {
            "url": url,
            "status": "Error",
            "error": "Could not connect to IPQS."
        }

    # Handles problems processing API response
    except (ValueError, TypeError):
        return {
            "url": url,
            "status": "Error",
            "error": "Could not read the IPQS response."
        }

# ----- URLscan.io Analysis Function -----

# - Domain registration information -
# Gets the domain's registration date and registrar using RDAP (registration data access protocol)
def get_domain_info(domain):

    # Removes www. so RDAP can look up the registered domain
    domain = domain.lower().strip()

    if domain.startswith("www."):
        domain = domain[4:]

    try:
        # Uses the correct RDAP server for the domain
        if domain.endswith(".com"):
            endpoint = (
                f"https://rdap.verisign.com/com/v1/domain/{domain}"
            )
        else:
            endpoint = f"https://rdap.org/domain/{domain}"

        response = httpx.get(
            endpoint,
            timeout=20,
            follow_redirects=True
        )

        data = response.json()

        domain_created = "Not found."
        domain_registrar = "Not found."

        # Finds the original registration date
        for event in data.get("events", []):

            if event.get("eventAction", "").lower() == "registration":

                created_date = event.get("eventDate")

                if created_date:
                    date = datetime.fromisoformat(
                        created_date.replace("Z", "+00:00")
                    )

                    day = date.day

                    # Adds the correct ending to the day
                    if 11 <= day <= 13:
                        suffix = "th"
                    else:
                        suffix = {
                            1: "st",
                            2: "nd",
                            3: "rd"
                        }.get(day % 10, "th")

                    # Displays only the month, day, and year
                    domain_created = (
                        f"{date.strftime('%B')} "
                        f"{day}{suffix}, "
                        f"{date.strftime('%Y')}"
                    )

                    break

        # Finds the domain registrar's name
        for entity in data.get("entities", []):

            if "registrar" in entity.get("roles", []):

                vcard = entity.get("vcardArray", [])

                if len(vcard) > 1:

                    for field in vcard[1]:

                        if field[0] == "fn":
                            domain_registrar = field[3]
                            break

                break

        return {
            "domain_created": domain_created,
            "domain_registrar": domain_registrar
        }

    except (httpx.RequestError, ValueError, TypeError, KeyError) as e:

        return {
            "domain_created": "Not found.",
            "domain_registrar": "Not found."
        }

# ----- URLscan.io URL Analysis -----

# Submits a URL to URLscan and retrives it's completed report
def analyze_urlscan(url):

    # Checks if the URLscan API key is configured
    if not URLSCAN_API_KEY:
        return {
            "url": url,
            "status": "Error",
            "error": "URLscan API key is not configured."
        }

    # URLscan API endpoint
    endpoint = "https://urlscan.io/api/v1/scan/"

    # Headers needed to authenticate with URLscan
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }

    # Information sent to URLscan for scanning
    payload = {
        "url": url,
        "visibility": "unlisted"
    }

    try:
        # Submits the URL for scanning
        response = httpx.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=20
        )

        # Checks whether URLscan accepted the submission
        if response.status_code not in (200, 201):
            return {
                "url": url,
                "status": "Submission failed",
                "http_code": response.status_code
            }

        # Reads the scan ID and report URL
        data = response.json()

        scan_id = data.get("uuid")
        result_url = data.get("result")

        # Checks if URLscan returned a scan ID
        if not scan_id:
            return {
                "url": url,
                "status": "Error",
                "message": "URLscan did not return a scan ID."
            }

        # URLscan result API endpoint
        result_endpoint = (
            f"https://urlscan.io/api/v1/result/{scan_id}/"
        )

        # Wait for URLscan to finish processing
        time.sleep(30)

        # Checks for the completed scan
        for attempt in range(8):

            result_response = httpx.get(
                result_endpoint,
                headers=headers,
                timeout=20
            )

            # Report is still processing
            if result_response.status_code == 404:
                time.sleep(10)
                continue

            # Handles other HTTP errors
            if result_response.status_code != 200:
                return {
                    "url": url,
                    "status": "Error",
                    "message": (
                        f"Submission failed: "
                        f"HTTP {result_response.status_code}"
                    )
                }

            # Reads the completed scan information
            scan_data = result_response.json()

            page = scan_data.get("page", {})

            # Gets the registered domain instead of the subdomain
            domain = (
                page.get("apexDomain")
                or page.get("domain", "")
            )

            domain_info = get_domain_info(domain)

            # Extracts the scan information
            return {
                "url": url,
                "status": "Report found",
                "page_title": page.get("title", "Not found."),
                "final_url": page.get("url", "Not found."),
                "domain_created": domain_info["domain_created"],
                "domain_registrar": domain_info["domain_registrar"],
                "ip": page.get("ip", "Not found."),
                "country": page.get("country", "Not found."),
                "result_url": result_url
            }

        # Scan did not finish within the period
        return {
            "url": url,
            "status": "Pending",
            "message": "Analysis report pending. No results available yet.",
            "result_url": result_url,
            "scan_id": scan_id
        }

    # Handles connection problems
    except httpx.RequestError:
        return {
            "url": url,
            "status": "Error",
            "message": "Could not connect to URLscan."
        }

    # Handles unexpected response data
    except (ValueError, KeyError, TypeError):
        return {
            "url": url,
            "status": "Error",
            "message": "Could not read the URLscan response."
        }

# ----- URLhaus Analysis -----
    
# Checks whether a URL is listed in the URLhaus malware database
def analyze_url_urlhaus(url):

    # Checks if the API key is configured
    if not URLHAUS_API_KEY:
        return {
            "url": url,
            "url_status": "Error",
            "error": "URLhaus Auth-Key is not configured."
        }

    # URLhaus API address
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"

    # Headers needed to connect to URLhaus
    headers = {
        "Auth-Key": URLHAUS_API_KEY,
        "User-Agent": "PhishCatcher/1.0"
    }

    # Sends the URL to URLhaus to check it
    try:
        response = httpx.post(
            endpoint,
            headers=headers,
            data={"url": url},
            timeout=20
        )

        # Checks if the request was successful
        if response.status_code != 200:
            return {
                "url": url,
                "url_status": "Error",
                "error": f"URLhaus returned HTTP {response.status_code}."
            }

        # Gets the results from URLhaus
        data = response.json()

        query_status = data.get("query_status")

        # Returns a message if the URL was not found
        if query_status == "no_results":
            return {
                "url": url,
                "url_status": "Not found"
            }

        # Checks if URLhaus returned a valid report
        if query_status != "ok":
            return {
                "url": url,
                "url_status": "Error",
                "error": f"URLhaus query status: {query_status or 'Unknown'}"
            }

        # Gets Spamhaus and SURBL results
        blacklists = data.get("blacklists", {}) or {}

        spamhaus = blacklists.get("spamhaus_dbl", "Unknown")
        surbl = blacklists.get("surbl", "Unknown")

        # Converts Spamhaus results into a simple status
        if spamhaus == "not listed":
            spamhaus_status = "Not blocked"
        elif spamhaus == "listed":
            spamhaus_status = "Blocked"
        else:
            spamhaus_status = "Unknown"

        # Converts SURBL results into a simple status
        if surbl == "not listed":
            surbl_status = "Not blocked"
        elif surbl == "listed":
            surbl_status = "Blocked"
        else:
            surbl_status = "Unknown"

        # Returns URLhaus analysis results
        return {
            "url": url,
            "url_status": data.get("url_status", "N/A"),
            "host": data.get("host", "N/A"),
            "date_added": data.get("date_added", "N/A"),
            "threat": data.get("threat", "N/A"),
            "urlhaus_blocklist": "Blocked",
            "spamhaus_dbl": spamhaus_status,
            "surbl": surbl_status
        }

    # Handles connection problems
    except httpx.RequestError:
        return {
            "url": url,
            "url_status": "Error",
            "error": "Could not connect to URLhaus."
        }

    # Handles errors when reading the results
    except (ValueError, TypeError, KeyError):
        return {
            "url": url,
            "url_status": "Error",
            "error": "Could not read the URLhaus response."
        }

# ----- Email Threat Intel Analysis -----

def analyze_tools(urls, attachment_hashes):

    # Store results separately
    results = {
        "url_results": [],
        "file_hash_results": [],
        "ipqs_results": [],
        "urlscan_results": [],
        "urlhaus_results": []
    }

    # Store all checks that will run
    tasks = []

    # All multiple checks to run at the same time
    with ThreadPoolExecutor(max_workers=10) as executor:

        # Check each URL once with VirusTotal and IPQS
        for url in dict.fromkeys(urls):

            # Starts checking URLs with VT
            tasks.append((
                "url_results",
                url,
                "url",
                executor.submit(analyze_url_virustotal, url)
            ))

            # Starts checking same URLs with IPQS
            tasks.append((
                "ipqs_results",
                url,
                "url",
                executor.submit(analyze_url_ipqs, url)
            ))

            # Starts checking the same URL with URLscan.io
            tasks.append((
                "urlscan_results",
                url,
                "url",
                executor.submit(analyze_urlscan, url)
            ))

            # Starts checking the same URL with URLhaus
            tasks.append((
                "urlhaus_results",
                url,
                "url",
                executor.submit(analyze_url_urlhaus, url)
            ))

        # Keeps track of attachment hashes we have already checked
        seen_hashes = set()

        # Goes thorugh each email attachment
        for attachment in attachment_hashes:

            # Gets the attachment's hash
            file_hash = attachment.get("sha256")

            # Skips attachements without a hash or with a duplicate hash
            if not file_hash or file_hash in seen_hashes:
                continue

            # Remebers the hash so it's not checked twice
            seen_hashes.add(file_hash)

            # Starts checking hash with VT
            tasks.append((
                "file_hash_results",
                file_hash,
                "file_hash",
                executor.submit(analyze_hash_virustotal, file_hash)
            ))

        # Collects each results
        for result_type, item, item_key, future in tasks:

            try:
                # Gets the result once this check finishes
                result = future.result()

            except Exception as e:
                # Saves the error if a check fails
                result = {
                    item_key: item,
                    "error": str(e)
                }

            # Adds the result to the correct list
            results[result_type].append(result)

    return results

# ----- Formatted VT Results -----

# Formats VT result for extension
def vt_result(result, indicator_type):
    
    # Displays a message when VT has no exisiting report
    if result.get("status") == "No report found":
        if indicator_type == "URL":
            indicator = result.get("url", "Unknown URL")
        else:
            indicator = result.get("sha256", "Unknown hash")

        if indicator_type == "SHA-256":
            indicator = f"{indicator[:12]}...{indicator[-8:]}"

        return (
            f"{indicator_type}: {indicator}\n"
            "No report analysis found."
        )

    # Displays a message if the analysis cannot be retrived
    if result.get("status") != "Report found":
        if indicator_type == "URL":
            indicator = result.get("url", "Unknown URL")
        else:
            indicator = result.get("sha256", "Unknown hash")

        if indicator_type == "SHA-256":
            indicator = f"{indicator[:12]}...{indicator[-8:]}"

        error = result.get(
            "error",
            result.get("status", "Unknown error")
        )

        return (
            f"{indicator_type}: {indicator}\n"
            f"Analysis unavailable: {error}"
        )

    # Gets the URL or attachment hash to display
    if indicator_type == "URL":
        indicator = result.get("url", "Unknown URL")
    else:
        indicator = result.get("sha256", "Unknown hash")

    if indicator_type == "SHA-256":
        indicator = f"{indicator[:12]}...{indicator[-8:]}"

    # Displays the VT detection counts
    return (
        f"{indicator_type}: {indicator}\n"
        f"Malicious: {result.get('malicious', 0)}\n"
        f"Suspicious: {result.get('suspicious', 0)}\n"
        f"Harmless: {result.get('harmless', 0)}"
    )

