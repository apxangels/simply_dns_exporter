[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-simply--dns--exporter-blue?logo=docker)](https://hub.docker.com/r/duoluotianshi/simply_dns_exporter)

# Simply DNS exporter
This exporter is designed as an alternative to checks performed using dns_exporter or blackbox_exporter, which do not support probing multiple targets through a single server. It is simple and fast, allowing you to check many targets at once and monitor their DNS records. </br>
</br>
Currently, only A and MX record checks are implemented. More query types may be added in the future.

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
docker pull duoluotianshi/simply_dns_exporter:latest
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
