import json
import logging
import uuid

from django.conf import settings
from typing import Dict

from .constants import (
    API_ENDPOINT_BASE,
    DEFAULT_DKIM_POLICY,
    DEFAULT_DMARC_POLICY,
    DEFAULT_MX_RECORD,
    DEFAULT_SPF_POLICY,
)
from .models import Zone, ZoneApiKey
from .pdns import pdns_replace_rrset
from .utils import remove_trailing_dot


class Credentials:
    def __init__(self, username: str, password: str, subdomain: str, fulldomain: str):
        assert fulldomain.startswith(f"{subdomain}.")
        self.username = username
        self.password = password
        self.subdomain = subdomain
        self.fulldomain = fulldomain

    def get_config(self) -> Dict[str, str]:
        return {
            "username": self.username,
            "password": self.password,
            "fulldomain": remove_trailing_dot(self.fulldomain),
            "subdomain": self.subdomain,
            # See: https://github.com/joohoi/acme-dns/issues/341
            "server_url": API_ENDPOINT_BASE,
            "allowfrom": [],
        }

    def get_config_json(self) -> str:
        return json.dumps(self.get_config(), indent=2)

    def get_lego_config(self) -> Dict[str, str]:
        return {
            remove_trailing_dot(self.fulldomain): self.get_config(),
        }

    def get_lego_config_json(self) -> str:
        return json.dumps(self.get_lego_config(), indent=2)


class InstantSubdomainCreatedInfo:
    PARENT_DOMAIN = "localhostcert.net."

    def __init__(self, username: str, password: str, subdomain: str):
        self.username = username
        self.password = password
        self.subdomain = subdomain

    def get_fulldomain(self) -> str:
        return f"{self.subdomain}.{InstantSubdomainCreatedInfo.PARENT_DOMAIN}"

    def get_credentials(self):
        return Credentials(
            self.username, self.password, self.subdomain, self.get_fulldomain()
        )


def create_instant_subdomain(is_delegate: bool) -> InstantSubdomainCreatedInfo:
    subdomain_name = str(uuid.uuid4())
    parent_name = InstantSubdomainCreatedInfo.PARENT_DOMAIN
    new_fqdn = f"{subdomain_name}.{parent_name}"

    logging.info(f"Creating instant domain {new_fqdn} for anonymous user")
    new_zone = Zone.objects.create(
        name=new_fqdn,
        owner=None,
        is_delegate=is_delegate,
    )
    zone_key, secret = ZoneApiKey.create(new_zone)

    return InstantSubdomainCreatedInfo(
        subdomain=subdomain_name,
        username=str(zone_key.id),
        password=secret,
    )

