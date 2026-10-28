
import base64
import httpx
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor

from config import VIRUSTOTAL_API_KEY
from config import IPQS_API_KEY


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
            "safe": not unsafe if isinstance(unsafe, bool) else None,
            "suspicious": data.get("suspicious"),
            "domain": data.get("domain"),
            "malware": data.get("malware"),
            "phishing": data.get("phishing"),
            "risk_score": data.get("risk_score"),
            "domain_age": domain_age
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

# ----- Email Threat Intel Analysis -----

def analyze_tools(urls, attachment_hashes):

    # Store results separately
    results = {
        "url_results": [],
        "file_hash_results": [],
        "ipqs_results": []
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

