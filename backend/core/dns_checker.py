import socket


def extract_domain(url: str) -> str:
    """Extract the root domain from a URL string."""
    domain = url.strip().lower()
    if domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http://"):
        domain = domain[7:]
    domain = domain.split("/")[0].split("?")[0]
    domain = domain.replace("www.", "")
    return domain


def check_dns(url: str) -> tuple:
    """
    Performs a DNS lookup to check if a domain actually exists.

    Returns:
        resolves (bool)    : True if domain resolves to an IP
        ip (str | None)    : The resolved IP, or None if failed
        error (str | None) : Error message if failed, or None on success
    """
    domain = extract_domain(url)

    if not domain:
        return False, None, "Empty domain after parsing"

    # A real domain must have at least one dot (e.g. "google.com")
    if "." not in domain:
        return False, None, f"'{domain}' is not a valid domain (no TLD)"

    try:
        ip = socket.gethostbyname(domain)
        return True, ip, None

    except socket.gaierror as e:
        return False, None, f"DNS resolution failed: {str(e)}"

    except Exception as e:
        return False, None, f"Unexpected error: {str(e)}"