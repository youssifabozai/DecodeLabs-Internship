import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "urgent", "immediately", "verify", "verification", "password", "reset",
    "login", "signin", "sign in", "account locked", "suspended", "limited",
    "payment", "billing", "invoice", "refund", "prize", "winner",
    "confidential", "do not share", "wire transfer", "gift card",
    "mfa", "otp", "code", "approve", "security alert"
}

AUTHORITY_KEYWORDS = {
    "ceo", "manager", "admin", "it support", "security team",
    "human resources", "hr", "finance department", "bank"
}

SENSITIVE_INFO_KEYWORDS = {
    "password", "otp", "verification code", "credit card", "card number",
    "bank account", "ssn", "national id", "login details", "credentials"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".hta",
    ".iso", ".img", ".jar", ".ps1", ".html", ".htm"
}

OFFICIAL_DOMAINS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com"],
    "google": ["google.com"],
    "facebook": ["facebook.com"],
    "apple": ["apple.com"],
    "netflix": ["netflix.com"],
    "decodelabs": ["decodelabs.tech"]
}


def extract_email_address(value):
    """
    Extracts an email address from strings like:
    CEO Name <ceo@example.com>
    """
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', value)
    return match.group(0).lower() if match else ""


def get_domain_from_email(email):
    if "@" not in email:
        return ""
    return email.split("@")[-1].lower()


def extract_urls(text):
    pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    return re.findall(pattern, text)


def normalize_url(url):
    if url.startswith("www."):
        return "http://" + url
    return url


def get_hostname(url):
    parsed = urlparse(normalize_url(url))
    return parsed.hostname.lower() if parsed.hostname else ""


def get_root_domain(hostname):
    """
    Simple root-domain approximation.
    Example:
    www.decodelabs.tech.login-update.com -> login-update.com

    Note: This is enough for a beginner project, but not a full public suffix parser.
    """
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def is_ip_address(hostname):
    return bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', hostname))


def check_url(url):
    red_flags = []
    score = 0

    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = get_hostname(url)
    root_domain = get_root_domain(hostname)

    if not hostname:
        return 0, ["Invalid or unreadable URL."]

    if parsed.scheme == "http":
        score += 1
        red_flags.append(f"URL uses HTTP instead of HTTPS: {url}")

    if is_ip_address(hostname):
        score += 3
        red_flags.append(f"URL uses an IP address instead of a normal domain: {url}")

    if root_domain in URL_SHORTENERS:
        score += 2
        red_flags.append(f"URL uses a URL shortener, which can hide the real destination: {url}")

    suspicious_terms = ["login", "verify", "secure", "update", "account", "billing", "payment", "reset"]
    if any(term in normalized.lower() for term in suspicious_terms):
        score += 1
        red_flags.append(f"URL contains security/account-related keywords: {url}")

    # Brand impersonation / lookalike domain check
    for brand, official_roots in OFFICIAL_DOMAINS.items():
        if brand in hostname and root_domain not in official_roots:
            score += 3
            red_flags.append(
                f"Possible brand impersonation: '{brand}' appears in the URL, "
                f"but the real root domain is '{root_domain}'. URL: {url}"
            )

    # Nested subdomain trap check
    labels = hostname.split(".")
    if len(labels) > 3:
        subdomain_part = ".".join(labels[:-2])
        for brand in OFFICIAL_DOMAINS:
            if brand in subdomain_part and root_domain not in OFFICIAL_DOMAINS[brand]:
                score += 3
                red_flags.append(
                    f"Nested subdomain trap: trusted-looking name appears in the subdomain, "
                    f"but the true root domain is '{root_domain}'. URL: {url}"
                )

    return score, red_flags


def check_attachments(attachments_text):
    red_flags = []
    score = 0

    if not attachments_text.strip():
        return score, red_flags

    attachments = [item.strip() for item in attachments_text.split(",") if item.strip()]

    for attachment in attachments:
        lower_attachment = attachment.lower()

        if any(lower_attachment.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            score += 3
            red_flags.append(
                f"Dangerous attachment type detected: {attachment}"
            )
        elif lower_attachment.endswith(".zip"):
            score += 1
            red_flags.append(
                f"Compressed attachment detected. ZIP files can hide malicious files: {attachment}"
            )
        elif lower_attachment.endswith(".pdf"):
            score += 0
        else:
            score += 1
            red_flags.append(
                f"Unusual attachment detected: {attachment}"
            )

    return score, red_flags


def check_message_content(subject, body):
    red_flags = []
    score = 0

    combined = f"{subject} {body}".lower()

    found_suspicious = sorted({word for word in SUSPICIOUS_KEYWORDS if word in combined})
    if found_suspicious:
        score += min(len(found_suspicious), 4)
        red_flags.append(
            "Suspicious keywords found: " + ", ".join(found_suspicious)
        )

    found_authority = sorted({word for word in AUTHORITY_KEYWORDS if word in combined})
    if found_authority:
        score += 2
        red_flags.append(
            "Authority pressure detected: " + ", ".join(found_authority)
        )

    found_sensitive = sorted({word for word in SENSITIVE_INFO_KEYWORDS if word in combined})
    if found_sensitive:
        score += 3
        red_flags.append(
            "Request for sensitive information detected: " + ", ".join(found_sensitive)
        )

    urgency_patterns = [
        "within 24 hours", "in 24 hours", "within 30 minutes",
        "immediate action", "act now", "final warning", "last chance"
    ]
    found_urgency = sorted({phrase for phrase in urgency_patterns if phrase in combined})
    if found_urgency:
        score += 3
        red_flags.append(
            "Urgency or time pressure detected: " + ", ".join(found_urgency)
        )

    if "do not tell" in combined or "do not share" in combined or "confidential" in combined:
        score += 2
        red_flags.append("Secrecy pressure detected. Legitimate requests rarely demand secrecy.")

    if "scan qr" in combined or "qr code" in combined:
        score += 2
        red_flags.append("QR code prompt detected. QR phishing can bypass normal URL inspection.")

    if re.search(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', combined):
        score += 1
        red_flags.append("Phone number detected. Could indicate callback phishing if no safe official channel is provided.")

    return score, red_flags


def check_headers(from_field, return_path):
    red_flags = []
    score = 0

    from_email = extract_email_address(from_field)
    return_email = extract_email_address(return_path)

    from_domain = get_domain_from_email(from_email)
    return_domain = get_domain_from_email(return_email)

    if from_email and return_email and from_domain != return_domain:
        score += 3
        red_flags.append(
            f"Sender-domain mismatch: From domain '{from_domain}' does not match Return-Path domain '{return_domain}'."
        )

    if from_field and not from_email:
        score += 1
        red_flags.append("From field does not contain a clear email address.")

    free_email_domains = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}
    if from_domain in free_email_domains and any(role in from_field.lower() for role in ["ceo", "admin", "support", "security", "finance"]):
        score += 2
        red_flags.append(
            f"Possible display-name spoofing: authority role uses free email domain '{from_domain}'."
        )

    return score, red_flags


def classify_risk(score):
    if score >= 8:
        return "Malicious", "Block and escalate to the security team."
    elif score >= 4:
        return "Suspicious", "Warn the user and verify through an official out-of-band channel."
    else:
        return "Safe", "Close or allow, but continue normal awareness."


def analyze_email(from_field, return_path, subject, body, attachments_text):
    total_score = 0
    red_flags = []

    header_score, header_flags = check_headers(from_field, return_path)
    total_score += header_score
    red_flags.extend(header_flags)

    content_score, content_flags = check_message_content(subject, body)
    total_score += content_score
    red_flags.extend(content_flags)

    urls = extract_urls(body)
    for url in urls:
        url_score, url_flags = check_url(url)
        total_score += url_score
        red_flags.extend(url_flags)

    attachment_score, attachment_flags = check_attachments(attachments_text)
    total_score += attachment_score
    red_flags.extend(attachment_flags)

    classification, action = classify_risk(total_score)

    return {
        "score": total_score,
        "classification": classification,
        "action": action,
        "red_flags": red_flags,
        "urls_found": urls
    }


def print_report(result):
    print("\n=== Phishing Analysis Report ===")
    print("Risk Score:", result["score"])
    print("Classification:", result["classification"])
    print("Recommended Action:", result["action"])

    if result["urls_found"]:
        print("\nURLs Found:")
        for url in result["urls_found"]:
            print("-", url)
    else:
        print("\nURLs Found: None")

    if result["red_flags"]:
        print("\nRed Flags Found:")
        for index, flag in enumerate(result["red_flags"], start=1):
            print(f"{index}. {flag}")

        print("\nWhy this message may be unsafe:")
        print(
            "The message contains one or more phishing indicators such as suspicious links, "
            "sender mismatch, urgency, authority pressure, sensitive information requests, "
            "or risky attachments."
        )
    else:
        print("\nRed Flags Found: None")
        print("\nWhy this message appears safe:")
        print("No major phishing indicators were detected by the checklist.")


def run_manual_analysis():
    print("\nEnter the email/message details.")
    print("If you do not have a field, leave it empty.\n")

    from_field = input("From: ")
    return_path = input("Return-Path: ")
    subject = input("Subject: ")
    print("Body: ")
    body = input()
    attachments = input("Attachments separated by commas, if any: ")

    result = analyze_email(from_field, return_path, subject, body, attachments)
    print_report(result)


def run_sample_analysis():
    from_field = "CEO Name <ceo.name@gmail.com>"
    return_path = "attacker@fake-billing-support.com"
    subject = "URGENT: Wire Transfer Required Within 30 Minutes"
    body = (
        "This is strictly confidential. Do not share this with anyone. "
        "Please verify the payment immediately using this link: "
        "http://company-secure-login.fake-billing-support.com/login "
        "Send confirmation once complete."
    )
    attachments = "invoice.html"

    print("\nRunning built-in phishing sample...")
    result = analyze_email(from_field, return_path, subject, body, attachments)
    print_report(result)


def main():
    print("=== Project 3: Phishing Awareness Analysis ===")
    print("Choose an option:")
    print("1. Analyze an email/message")
    print("2. Run built-in phishing sample")

    choice = input("Enter your choice (1/2): ")

    if choice == "1":
        run_manual_analysis()
    elif choice == "2":
        run_sample_analysis()
    else:
        print("Invalid choice. Please choose 1 or 2.")


if __name__ == "__main__":
    main()
