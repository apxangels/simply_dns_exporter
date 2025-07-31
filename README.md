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
