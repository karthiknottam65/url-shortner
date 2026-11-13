import json
import os
import re
import string
import random
import urllib.request
import urllib.error
from urllib.parse import urlparse
import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["TABLE_NAME"])
SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "").strip()

ALPHABET = string.ascii_letters + string.digits
DANGEROUS_EXTENSIONS = (".exe", ".bat", ".cmd", ".scr", ".msi", ".vbs", ".ps1", ".apk")
IP_HOST_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

THREAT_LABELS = {
    "MALWARE": "Malware / Virus Detected",
    "SOCIAL_ENGINEERING": "Phishing / Deceptive Site Detected",
    "UNWANTED_SOFTWARE": "Unwanted / Harmful Software Detected",
    "POTENTIALLY_HARMFUL_APPLICATION": "Potentially Harmful Application Detected",
}

def generate_code(length=6):
    return "".join(random.choices(ALPHABET, k=length))

def scan_url_safety(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return (False, "Invalid or Unsafe Protocol", "Only standard HTTP and HTTPS links are permitted.")

    hostname = parsed.hostname or ""
    path_lower = (parsed.path or "").lower()

    if IP_HOST_PATTERN.match(hostname):
        return (False, "Suspicious IP Address Blocked", "Links pointing to raw IP addresses are blocked due to high phishing risk.")

    if path_lower.endswith(DANGEROUS_EXTENSIONS):
        return (False, "Dangerous File Blocked", f"Direct links to executable files ({os.path.splitext(path_lower)[1]}) are blocked for safety.")

    if SAFE_BROWSING_API_KEY:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "serverless-url-shortener", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        req = urllib.request.Request(
            endpoint, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                matches = result.get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType", "MALWARE")
                    title = THREAT_LABELS.get(threat_type, "Security Threat Detected")
                    return (False, title, "This URL was flagged by Google Safe Browsing as unsafe. Shortening blocked.")
        except Exception:
            pass

    return True, "Safe", "URL passed security verification."

def shorten_url(event, context):
    try:
        body = json.loads(event.get("body") or "{}")
        long_url = (body.get("url") or "").strip()

        if not long_url:
            return {"statusCode": 400, "headers": {"Content-Type": "application/json"}, "body": json.dumps({"error": "Please enter a valid URL."})}

        is_safe, threat_title, alert_message = scan_url_safety(long_url)
        if not is_safe:
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"safe": False, "threat_title": threat_title, "alert_message": alert_message}),
            }

        short_code = generate_code()
        table.put_item(Item={"short_code": short_code, "long_url": long_url})
        domain = event["requestContext"]["domainName"]
        short_url = f"https://{domain}/{short_code}"

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"safe": True, "short_code": short_code, "short_url": short_url}),
        }
    except Exception as exc:
        return {"statusCode": 500, "headers": {"Content-Type": "application/json"}, "body": json.dumps({"error": str(exc)})}

def redirect_url(event, context):
    short_code = (event.get("pathParameters") or {}).get("short_code", "")
    resp = table.get_item(Key={"short_code": short_code})
    item = resp.get("Item")
    if not item:
        return {"statusCode": 404, "headers": {"Content-Type": "text/plain"}, "body": "Short URL not found."}
    return {"statusCode": 301, "headers": {"Location": item["long_url"]}, "body": ""}