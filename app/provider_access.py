"""Constrain authenticated requests to official HTTPS origins, without redirects."""
from urllib.parse import urlsplit
import requests

class ProviderSession(requests.Session):
    def request(self, method, url, **kwargs):
        parsed = urlsplit(url)
        params = kwargs.get('params') or {}
        headers = kwargs.get('headers') or {}
        authenticated = any(k.lower() in ('authorization', 'x-api-key') for k in headers) or any(
            k.lower() in ('key', 'token', 'organization_id') for k in params)
        if authenticated:
            if parsed.scheme != 'https' or parsed.hostname not in ('api.shodan.io', 'api.platform.censys.io') or parsed.port not in (None,443):
                raise ValueError('Authenticated provider request blocked: unexpected endpoint')
            kwargs['allow_redirects'] = False
        return super().request(method, url, **kwargs)
