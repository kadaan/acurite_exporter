# acurite_exporter [![Build Status](https://travis-ci.org/kadaan/acurite_exporter.svg?branch=master)](https://travis-ci.org/kadaan/acurite_exporter) [![Coverage Status](https://img.shields.io/coveralls/github/kadaan/acurite_exporter/master.svg)](https://coveralls.io/github/kadaan/acurite_exporter) [![Go Report Card](https://goreportcard.com/badge/github.com/kadaan/acurite_exporter)](https://goreportcard.com/report/github.com/kadaan/acurite_exporter)

acurite_exporter is a command line tool to export information about your Acurite
sensors in a format that can be scraped by [Prometheus](http://prometheus.io).

### Setup

To collect Acurite metrics the POST requests from the Acurite SmartHub or Acurite Access need to be directed to this service.  To do that you can run a DNS server such as [Unbound](https://nlnetlabs.nl/projects/unbound).  Configure Unbound to resolve DNS request for atlasapi.myacurite.com to the server running acurite_exporter.  The SmartHub and Access communicate over SSL, but don't validate the certificate.  The acurite_exporter doesn't support SSL, so you need to run something like [nginx](https://www.nginx.com/) to handle the SSL.

### Running

Running the acurite_exporter is as simple as just starting `acurite_expoter`.  There are configuration options that can be specified, but the defaults are generally fine.

### Example Unbound Configuration

```yaml
server:
  interface: 0.0.0.0
    verbosity: 1
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    access-control: 10.0.0.0/8 allow
    access-control: 127.0.0.0/8 allow
    access-control: 192.168.0.0/16 allow
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    prefetch: yes
    num-threads: 2
    msg-cache-slabs: 8
    rrset-cache-slabs: 8
    infra-cache-slabs: 8
    key-cache-slabs: 8
    rrset-cache-size: 128m
    msg-cache-size: 32m
    so-rcvbuf: 1m
    private-address: 192.168.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-domain: "internal"
    unwanted-reply-threshold: 10000
    do-not-query-localhost: no
    val-clean-additional: yes
    username: "_unbound"

    local-zone: "myacurite.com." transparent
    local-data: "atlasapi.myacurite.com. IN A 192.168.1.68"

forward-zone:
  name: "."
  forward-addr: 1.1.1.1
  forward-addr: 1.0.0.1
  forward-addr: 8.8.4.4
  forward-addr: 8.8.8.8
```

### Example Nginx configuration

```
server {
    listen 80;
    server_name atlasapi.myacurite.com;
    return 444;
}

server {
    listen 443 ssl http2;

    server_name atlasapi.myacurite.com;

    limit_conn arbeit 32;

    ## Access and error logs.
    access_log /var/log/nginx/myacurite_access_log;
    error_log /var/log/nginx/myacurite_error_log;

    ## Keep alive timeout set to a greater value for SSL/TLS.
    keepalive_timeout 75 75;

    ## See the keepalive_timeout directive in nginx.conf.
    ## Server certificate and key.
    ssl_certificate     /usr/local/var/lib/certs/root/ca/intermediate/certs/self_signed.chained.cert.pem;
    ssl_certificate_key /usr/local/var/lib/certs/root/ca/intermediate/private/self_signed.key.pem;

    ssl_protocols  TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4;
    ssl_prefer_server_ciphers on;

    location /weatherstation/updateweatherstation {
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect http:// https://;

        add_header Pragma "no-cache";

        proxy_pass http://127.0.0.1:9519;
    }
}
```