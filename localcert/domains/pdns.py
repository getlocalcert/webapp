import logging

from .utils import CustomExceptionServerError
from datetime import datetime
from django.conf import settings
from typing import List
from cloudflare import Cloudflare


ZONE_IDS = {
    "localcert.net.": "ab2d04b0ccf31906dd87900f0db11f73",
    "localhostcert.net.": "ac1335db9f052915b076c0de09e06443",
}


client = Cloudflare(api_token=os.environ.get("CLOUDFLARE_TOKEN"))


# TODO: Some records are set by wildcard, hardcode these
def pdns_describe_domain(domain: str) -> dict:
    assert domain.endswith(".")
    logging.debug(f"[PDNS] Describe {domain}")

    for k, v in ZONE_IDS.items():
        if domain.endswith(f".{k}")
            zone_id = v
            break
    else:
        # Ooops
        return {}

    # CF doesn't use trailing dot
    domain = domain[:-1]

    # Two lookups:
    #   <domain>.<zone> (exact)
    # *.<domain>.<zone> (endswith)
    results = client.dns.records.list(
        zone_id=zone_id,
        name={"endswith": f".{domain}"},
        type="TXT",
    ).result
    r2 = client.dns.records.list(
        zone_id=zone_id,
        name={"exact": domain},
        type="TXT",
    ).result
    results.extend(r2)

    rrsets = []
    for result in results:
        rrset.append({
            "type": "TXT",
            "name": result.name,
            "content": result.content,
            "ttl": result.ttl,
        })
    return { "rrsets": rrsets }


def pdns_replace_rrset(
    zone_name: str, rr_name: str, rr_type: str, ttl: int, record_contents: List[str]
):
    """
    record_contents - Records from least recently added
    """
    assert rr_name.endswith(".")
    assert rr_name.endswith(zone_name)
    assert rr_type  == "TXT"

    # CF doesn't use trailing dot
    rr_name = rr_name[:-1]

    # Collect the existing content
    zone_id = ZONE_IDS[zone_name]
    results = client.dns.records.list(
        zone_id=zone_id,
        name=rr_name,
        type=rr_type,
    ).result

    for record in results:
        if record.content not in record_contents:
            # Delete records that are no longer needed
            client.dns.records.delete(
                zone_id=zone_id,
                dns_record_id=record.id,
            )
        else:
            # Don't alter records that already exist
            record_contents.remove(record.content)

    for content in record_contents:
        # Create anything that's new
        client.dns.records.create(
            zone_id=zone_id,
            name=rr_name,
            type=rr_type,
            content=content,
        )

    # success
    return

