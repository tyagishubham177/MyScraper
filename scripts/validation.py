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

def configured_product_url(value):
    """Recover the known duplicated-path data entry without guessing identity.

    An embedded canonical URL must use the exact allowed host. Any outer or
    trailing product slug must match it. Other malformed values still fail.
    """
    if isinstance(value, str):
        origin = 'https://shop.amul.com'
        parts = value.strip().split(origin)
        if len(parts) >= 3 and parts[0] == '':
            # Parse each copied route fragment, rather than selecting an
            # arbitrary embedded URL. Every named product must agree.
            final = re.fullmatch(
                r'/en/product/(?P<slug>[a-z0-9-]+)'
                r'(?:(?:/en)?/product/(?P=slug))*/?', parts[-1]
            )
            if final:
                slug = final['slug']
                consistent = True
                for prefix in parts[1:-1]:
                    if prefix in ('/en', '/en/product', '/en/product/'):
                        continue
                    outer = re.fullmatch(r'/en/product/([a-z0-9-]+)/?', prefix)
                    if not outer or outer[1] != slug:
                        consistent = False
                        break
                if consistent:
                    return product_url(origin + '/en/product/' + slug)
    return product_url(value)

def pincode(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{6}', value):
        raise ValueError("Pincode must contain exactly six digits")
    return value
