# README

## Cheat Sheet

    $ docker compose build
    $ docker compose --env-file=dev.env up

    $ docker container ls
    $ docker logs <id>

## Fresh Start

For local testing it's nice to spin up a test environment.

First clear any old data:

    $ rm -Rf data/


Build everything:

    $ docker compose build


Start just the database:


    $ docker compose --env-file=dev.env up db -d

Open a shell in the database:

    $ docker exec -it --env-file=dev.env mvp-db-1 /bin/bash -c "PGPASSWORD=\${POSTGRES_PASSWORD} psql -U \${POSTGRES_USER}"
    postgres=# CREATE DATABASE "localcert-web";
    postgres=# CREATE DATABASE "localcert-pdns";

Create a fresh DNS server container (the normal one can't start without the tables):

    $ docker run -it --env-file=dev.env --net localcert-net mvp-pdns /bin/bash -c "PGPASSWORD=\${POSTGRES_PASSWORD} psql -h db -U \${POSTGRES_USER} -d \${LOCALCERT_PDNS_DB_NAME} -a -f /usr/share/doc/pdns-backend-pgsql/schema.pgsql.sql"

Bring up all the containers:

    $ docker compose down
    $ docker compose --env-file=dev.env up -d

Open a shell to the web server to migrate the database:

    $ docker exec -it --env-file=dev.env mvp-web-1 python manage.py migrate

Restart everything and it should now run.

    $ docker compose down
    $ docker compose --env-file=dev.env up -d

See steps to add zones below.

Edit /etc/hosts to point to localhost:

    127.0.0.1       console.getlocalcert.net
    127.0.0.1       api.getlocalcert.net

Open http://console.getlocalcert.net/
You may need to clear cookies or clear HSTS settings.


## Django Testing

Clear old database, if needed:

    $ rm -Rf test-data/


Start local DNS and PG containers:

    $ docker compose -f docker-compose-test.yml build
    $ docker compose -f docker-compose-test.yml --env-file=test.env up


You should see the PDNS API online (it replies "Not Found"):

    $ curl 127.0.0.1:8081/
    Not Found


Setup testing env:

    $ source venv/bin/activate
    $ source test.env
    $ pip install -r requirements-dev.txt


Run tests:

    $ python manage.py test


Optionally run in parallel for a speedup:

    $ python manage.py test --parallel 12


## Additional production notes

You'll want to add nameservers for each of the domain names we control

    $ docker run -it --env-file=prod.env --net localcert-net getlocalcert-webapp-pdns /bin/bash

    # pdnsutil create-zone corpnet.work
    # pdnsutil add-record corpnet.work @ NS 3600 ns1.getlocalcert.net
    # pdnsutil add-record corpnet.work @ NS 3600 ns2.getlocalcert.net
    # pdnsutil add-record corpnet.work _psl TXT 3600 "\"https://github.com/publicsuffix/list/pull/1798\""

    # pdnsutil create-zone localcert.net
    # pdnsutil add-record localcert.net @ NS 3600 ns1.getlocalcert.net
    # pdnsutil add-record localcert.net @ NS 3600 ns2.getlocalcert.net
    # pdnsutil add-record localcert.net _psl TXT 3600 "\"https://github.com/publicsuffix/list/pull/1798\""

    # pdnsutil create-zone localhostcert.net
    # pdnsutil add-record localhostcert.net @ NS 3600 ns1.getlocalcert.net
    # pdnsutil add-record localhostcert.net @ NS 3600 ns2.getlocalcert.net
    # pdnsutil add-record localhostcert.net _psl TXT 3600 "\"https://github.com/publicsuffix/list/pull/1798\""

Complete with MX, SPF, DKIM, DMARC:

    localhostcert.net       3600    IN      SOA     ns1.getlocalcert.net soa-admin.robalexdev.com 1 10800 3600 604800 3600
    localhostcert.net       3600    IN      NS      ns1.getlocalcert.net
    localhostcert.net       3600    IN      NS      ns2.getlocalcert.net
    localhostcert.net       3600    IN      MX      0 .
    localhostcert.net       3600    IN      TXT     "v=spf1 -all"
    _dmarc.localhostcert.net        3600    IN      TXT     "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"
    *._domainkey.localhostcert.net  3600    IN      TXT     "v=DKIM1; p="

Check with https://mxtoolbox.com/


We'll also need to add glue records to our DNS to allow lookups.
[See here](https://www.namecheap.com/support/knowledgebase/article.aspx/768/10/how-do-i-register-personal-nameservers-for-my-domain/).
These are added to getlocalcert.net as ns1/ns2 such that the IP address is actually stored in the root DNS servers.

## Pre-commit testing

In one terminal run:

    $ source test.env
    $ docker compose -f docker-compose-test.yml --env-file=test.env build
    $ docker compose -f docker-compose-test.yml --env-file=test.env up

In another run the tests (or commit, which triggers the tests):

    $ source test.env
    $ python manage.py test [--parallel 12]
    $ git commit


## Python upgrades

Install:

    $ pip install pip-upgrader

Run

    $ pip-upgrader


## Deployment

    $ ssh <user>@<ip> ./deploy/getlocalcert-webapp/deploy/prod-pull.sh
    $ ssh <user>@<ip> ./deploy/getlocalcert-webapp/deploy/prod-deploy.sh

Consider doing a prune as well to manage disk space:

    $ ssh <user>@<ip> ./deploy/getlocalcert-webapp/deploy/prod-prune.sh

### With Migrations

    $ docker compose --env-file=prod.env build
    $ docker compose --env-file=prod.env down
    $ docker compose --env-file=prod.env up -d
    $ docker exec -it --env-file=prod.env getlocalcert-webapp-web-1 python manage.py migrate

XXX this runs the service before the migration is applied, probably want to do it first


## Important References

* PDNS API - https://doc.powerdns.com/authoritative/http-api/index.html
* acme-dns - https://github.com/joohoi/acme-dns/


## ACME notes

Manually create acme.json in PROD

    $ echo "{}" > acme.json
    $ chmod 0600 acme.json


## systemd notes

Ubuntu runs a DNS stub resolver locally on port 53.
This needs to be turned off, in favor of a remote resolver, as it conflicts with PDNS.

Check if it's running:

	$ sudo lsof -i :53

Turn it off:

1. Edit /etc/systemd/resolved.conf

	[Resolve]
	DNS=1.1.1.1
	DNSStubListener=no

2. Run:

	$ ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

Verify:

	$ curl google.com
	$ sudo lsof -i :53


