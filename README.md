[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-simply--dns--exporter-blue?logo=docker)](https://hub.docker.com/r/apxangels/simply-dns-exporter)

# Simply DNS exporter
This exporter is designed as an alternative to checks performed using dns_exporter or blackbox_exporter, which do not support probing multiple targets through a single server. It is simple and fast, allowing you to check many targets at once and monitor their DNS records. </br>
</br>
Two probers are available:
- `dns` — simple A or MX lookup for a single target.
- `dig` — dig-like lookup that resolves NS, A, CNAME, MX and TXT records for the target domain, plus `autodiscover.<domain>`, `selector1._domainkey.<domain>` and `selector2._domainkey.<domain>`. Every resolved value is exposed as a murmurhash2 hash (per record, per record type, and one combined hash for the whole domain), so you can alert on any DNS change.

## How to Use
Clean python way
```
pip install -r requirements.txt
python /app/exporter.py -config.file=/app/config.yml
```
Docker / docker compose way
```
# build by yourself
docker build -t .
# And run
docker run -d \
  -p 9116:9116 \
  -v $(pwd)/config.yml:/app/config.yml \
  --name simply_dns_exporter     \
  simply_dns_exporter
```
Or use compose file in repo:
```
docker compose up -d
```
Or download from hub:
```
docker pull apxangels/simply-dns-exporter:latest
```
## How to configure
A sample configuration file might look like this
```
listen_address: ":9116"    # Exporter port
modules:
  google-dns:              # Module name
    prober: dns            # Currently only 'dns' is supported (not DoT or DoH)
    protocol: ipv4         # Only IPv4 is supported
    query_type: A          # A or MX record
    server: "8.8.8.8"      # DNS server
    timeout: 5s            # Request timeout
  cloudflare-dns:
    prober: dns
    protocol: ipv4
    query_type: MX
    server: "1.1.1.1"
    timeout: 5s
  dig-google-dns:
    prober: dig            # dig-like probe: NS, A, CNAME, MX, TXT + autodiscover/DKIM selectors
    protocol: ipv4
    server: "8.8.8.8"
    timeout: 5s
```
Response from request like `http://localhost:9116/probe?module=google-dns&target=ya.ru` will look like
```
# HELP dnsp_probe_success Probe success (1/0)
# TYPE dnsp_probe_success gauge
dnsp_probe_success 1.0
# HELP dnsp_probe_dns_rcode DNS rcode
# TYPE dnsp_probe_dns_rcode gauge
dnsp_probe_dns_rcode{rcode="NOERROR"} 1.0
# HELP dnsp_probe_dns_duration_seconds DNS probe durations
# TYPE dnsp_probe_dns_duration_seconds gauge
dnsp_probe_dns_duration_seconds{phase="connect"} 0.01900535098684486
dnsp_probe_dns_duration_seconds{phase="request"} 0.039169208001112565
dnsp_probe_dns_duration_seconds{phase="resolve"} 0.05840433201228734
# HELP dnsp_probe_ttl_seconds Min TTL for A records
# TYPE dnsp_probe_ttl_seconds gauge
dnsp_probe_ttl_seconds 300.0
# HELP dnsp_probe_ip_addr Resolved A record
# TYPE dnsp_probe_ip_addr gauge
dnsp_probe_ip_addr{domain="ya.ru",ip_A_record="185.71.64.200"} 1.0
# HELP dnsp_probe_ip_addr_hash murmurhash2 hash of sorted A records
# TYPE dnsp_probe_ip_addr_hash gauge
dnsp_probe_ip_addr_hash 7.44122439e+08
```

Response from a request like `http://localhost:9116/probe?module=dig-google-dns&target=example.com` looks like this (truncated):
```
# HELP dnsp_probe_dns_rcode DNS rcode per queried record
# TYPE dnsp_probe_dns_rcode gauge
dnsp_probe_dns_rcode{record_name="example.com",record_type="NS",rcode="NOERROR"} 1.0
dnsp_probe_dns_rcode{record_name="example.com",record_type="A",rcode="NOERROR"} 1.0
dnsp_probe_dns_rcode{record_name="example.com",record_type="MX",rcode="NOERROR"} 1.0
dnsp_probe_dns_rcode{record_name="example.com",record_type="TXT",rcode="NOERROR"} 1.0
dnsp_probe_dns_rcode{record_name="autodiscover.example.com",record_type="CNAME",rcode="NOERROR"} 1.0
dnsp_probe_dns_rcode{record_name="selector1._domainkey.example.com",record_type="TXT",rcode="NOERROR"} 1.0
# HELP dnsp_probe_dig_ttl_seconds Min TTL for a queried record
# TYPE dnsp_probe_dig_ttl_seconds gauge
dnsp_probe_dig_ttl_seconds{record_name="example.com",record_type="A"} 300.0
# HELP dnsp_probe_dig_record Resolved dig record (existence flag)
# TYPE dnsp_probe_dig_record gauge
dnsp_probe_dig_record{record_name="example.com",record_type="A",value="93.184.216.34"} 1.0
dnsp_probe_dig_record{record_name="selector1._domainkey.example.com",record_type="TXT",value="v=DKIM1; k=rsa; p=..."} 1.0
# HELP dnsp_probe_dig_record_hash murmurhash2 hash of a single record value
# TYPE dnsp_probe_dig_record_hash gauge
dnsp_probe_dig_record_hash{record_name="example.com",record_type="A",value="93.184.216.34"} 2.120760881e+09
# HELP dnsp_probe_dig_record_hash_all murmurhash2 hash of all sorted values for one record_name/record_type
# TYPE dnsp_probe_dig_record_hash_all gauge
dnsp_probe_dig_record_hash_all{record_name="example.com",record_type="A"} 2.120760881e+09
# HELP dnsp_probe_dig_domain_hash murmurhash2 hash of every resolved value for the domain, use to detect any DNS change
# TYPE dnsp_probe_dig_domain_hash gauge
dnsp_probe_dig_domain_hash{domain="example.com"} 2.945981419e+09
```
The `dnsp_probe_dig_domain_hash` metric changes whenever *any* NS/A/CNAME/MX/TXT/autodiscover/DKIM value for the domain changes, so it is convenient for a single alert rule (e.g. `changes(dnsp_probe_dig_domain_hash[1h]) > 0`).
