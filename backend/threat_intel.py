
import base64
import httpx

from config import VIRUSTOTAL_API_KEY

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

# ----- VirusTotal -----

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

# ----- Email Threat Intel Analysis -----

# Analyses extracted email links and attachment hashes using VT
def analyze_tools(urls, attachment_hashes):

    # Stores the results for URLs and Hashes
    results = {
        "url_results": [],
        "file_hash_results": [],
        "urlscan_results": []
    }

    # Check each URL with VT
    for url in dict.fromkeys(urls):
        results["url_results"].append(
            analyze_url_virustotal(url)
        )

    # Collects hashes from email attachments
    unique_hashes = dict.fromkeys(
        attachment["sha256"]
        for attachment in attachment_hashes
    )

    # Checks each attachment hash with VT
    for file_hash in unique_hashes:
        results["file_hash_results"].append(
            analyze_hash_virustotal(file_hash)
        )

    # Returns collected results
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

