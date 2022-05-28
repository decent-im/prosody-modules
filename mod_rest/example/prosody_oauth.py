from oauthlib.oauth2 import LegacyApplicationClient
from requests_oauthlib import OAuth2Session


class ProsodyRestClient(LegacyApplicationClient):
    pass


class ProsodyRestSession(OAuth2Session):
    def __init__(self, base_url=None, token_url=None, rest_url=None, *args, **kwargs):
        if base_url and not token_url:
            token_url = base_url + "/oauth2/token"
        if base_url and not rest_url:
            rest_url = base_url + "/rest"
        self._prosody_rest_url = rest_url
        self._prosody_token_url = token_url

        super().__init__(client=ProsodyRestClient(*args, **kwargs))

    def fetch_token(self, *args, **kwargs):
        return super().fetch_token(token_url=self._prosody_token_url, *args, **kwargs)

    def xmpp(self, json=None, *args, **kwargs):
        return self.post(self._prosody_rest_url, json=json, *args, **kwargs)


if __name__ == "__main__":
    # Example usage

    # from prosody_oauth import ProsodyRestSession
    from getpass import getpass

    p = ProsodyRestSession(base_url=input("Base URL: "), client_id="app")
    
    p.fetch_token(username=input("XMPP Address: "), password=getpass("Password: "))

    print(p.xmpp(json={"disco": True, "to": "jabber.org"}).json())
