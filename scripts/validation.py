"""Input contracts shared by checker and offline repair tools."""
import re
from urllib.parse import urlsplit, urlunsplit

class CheckError(RuntimeError):
    """No reliable availability decision can be made."""

def product_url(value):
    if not isinstance(value, str):
        raise ValueError("Product URL must be text")
    value = value.strip()
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.netloc != 'shop.amul.com'
            or not re.fullmatch(r'/en/product/[a-z0-9-]+/?', parsed.path)
            or parsed.query or parsed.fragment):
        raise ValueError("Expected a canonical HTTPS shop.amul.com/en/product/ URL")
    return urlunsplit(('https', 'shop.amul.com', parsed.path.rstrip('/'), '', ''))

def pincode(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{6}', value):
        raise ValueError("Pincode must contain exactly six digits")
    return value
