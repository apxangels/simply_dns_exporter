#!/usr/bin/env python3
import argparse
import hashlib
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.resolver
import yaml

from prometheus_client import CollectorRegistry, Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST

# ---------- utils ----------
# Should supports formats 5s / 5ms
def parse_duration(s: str) -> float:
    # поддержка "5s", "500ms"
    s = str(s).strip().lower()
    if s.endswith("ms"):
        return float(s[:-2]) / 1000.0
    if s.endswith("s"):
        return float(s[:-1])
    return float(s)

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def dns_query_a_udp(name: str, server: str, timeout: float):
    # Create DNS query
    q = dns.message.make_query(name, dns.rdatatype.A)
    # Send request as UDP query
    t0 = time.perf_counter()
    resp = dns.query.udp(q, server, timeout=timeout, ignore_unexpected=True)
    t1 = time.perf_counter()
    return resp, (t1 - t0)

def dns_query_mx_udp(name: str, server: str, timeout: float):
    q = dns.message.make_query(name, dns.rdatatype.MX)
    t0 = time.perf_counter()
    resp = dns.query.udp(q, server, timeout=timeout, ignore_unexpected=True)
    t1 = time.perf_counter()
    return resp, (t1 - t0)


def tcp_connect_check(server: str, port: int, timeout: float):
    t0 = time.perf_counter()
    with socket.create_connection((server, port), timeout=timeout):
        pass
    t1 = time.perf_counter()
    return (t1 - t0)

def extract_a_records_and_min_ttl(resp: dns.message.Message):
    ips = []
    min_ttl = None
    for ans in resp.answer:
        if ans.rdtype == dns.rdatatype.A:
            for rr in ans:
                ip = rr.address
                ips.append(ip)
                ttl = ans.ttl
                if min_ttl is None or ttl < min_ttl:
                    min_ttl = ttl
    return ips, min_ttl

def extract_mx_records_and_min_ttl(resp: dns.message.Message):
    mx_list = []
    min_ttl = None
    for ans in resp.answer:
        if ans.rdtype == dns.rdatatype.MX:
            for rr in ans:
                mx_host = str(rr.exchange).rstrip('.')
                pref = rr.preference
                mx_list.append((pref, mx_host))
                ttl = ans.ttl
                if min_ttl is None or ttl < min_ttl:
                    min_ttl = ttl
    return mx_list, min_ttl

# ---------- HTTP handler ----------
class ProbeHandler(BaseHTTPRequestHandler):
    server_version = "dnsp_exporter/0.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/probe":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return

        params = parse_qs(parsed.query)
        module = params.get("module", [None])[0]
        target = params.get("target", [None])[0]

        if not module or not target:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"usage: /probe?module=<name>&target=<domain>")
            return

        cfg = self.server.config
        mod = cfg["modules"].get(module)
        if not mod:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"unknown module: {module}".encode("utf-8"))
            return

        # defaults / validation
        if str(mod.get("prober", "dns")) != "dns":
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"only prober=dns is supported")
            return

        server_ip = str(mod.get("server", "")).strip()
        if not server_ip:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"module.server is required")
            return

        query_type = str(mod.get("query_type")).upper()
        if query_type not in ("A", "MX"):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"only query_type=A or query_type=MX is supported")
            return

        timeout_s = parse_duration(mod.get("timeout", "5s"))

        # registry for one response
        registry = CollectorRegistry()
        # Gauges
        g_success = Gauge("dnsp_probe_success", "Probe success (1/0)", registry=registry)
        g_rcode = Gauge("dnsp_probe_dns_rcode", "DNS rcode", ["rcode"], registry=registry)
        g_dur = Gauge("dnsp_probe_dns_duration_seconds", "DNS probe durations", ["phase"], registry=registry)
        g_ttl = Gauge("dnsp_probe_ttl_seconds", "Min TTL for A records", registry=registry)
        if query_type == "A":
            g_ip = Gauge("dnsp_probe_ip_addr", "Resolved A record", ["domain", "ip_A_record"], registry=registry)
            g_hash = Gauge("dnsp_probe_ip_addr_hash", "SHA256 hash of sorted A records", ["hash"], registry=registry)
        if query_type == "MX":
            g_mx = Gauge("dnsp_probe_mx_record", "Resolved MX record", ["domain", "exchange", "preference"], registry=registry)

        overall_start = time.perf_counter()
        success = 0
        rcode_name = "UNKNOWN"
        ip_list = []
        min_ttl = None

        try:
            # "connect" — fast tcp check for DNS server
            connect_time = tcp_connect_check(server_ip, 53, timeout_s)
            g_dur.labels(phase="connect").set(connect_time)

            # "request" — time of DNS query
            if query_type == "A":
                resp, req_time = dns_query_a_udp(target, server_ip, timeout_s)
                g_dur.labels(phase="request").set(req_time)

                rcode_val = resp.rcode()
                rcode_name = dns.rcode.to_text(rcode_val)
                g_rcode.labels(rcode=rcode_name).set(1)

                if rcode_val == dns.rcode.NOERROR:
                    ip_list, min_ttl = extract_a_records_and_min_ttl(resp)
                    if ip_list:
                        for ip in sorted(set(ip_list)):
                            g_ip.labels(domain=target, ip_A_record=ip).set(1)
                        if min_ttl is not None:
                            g_ttl.set(float(min_ttl))
                        hash_input = ",".join(sorted(ip_list))
                        g_hash.labels(hash=sha256_hex(hash_input)).set(1)
                        success = 1
            elif query_type == "MX":
                resp, req_time = dns_query_mx_udp(target, server_ip, timeout_s)
                g_dur.labels(phase="request").set(req_time)

                rcode_val = resp.rcode()
                rcode_name = dns.rcode.to_text(rcode_val)
                g_rcode.labels(rcode=rcode_name).set(1)

                if rcode_val == dns.rcode.NOERROR:
                    mx_list, min_ttl = extract_mx_records_and_min_ttl(resp)
                    if mx_list:
                        for pref, exch in sorted(set(mx_list)):
                            g_mx.labels(domain=target, exchange=exch, preference=str(pref)).set(1)
                        if min_ttl is not None:
                            g_ttl.set(float(min_ttl))
                        success = 1

        except socket.timeout:
            rcode_name = "TIMEOUT"
            g_rcode.labels(rcode=rcode_name).set(1)
            success = 0
        except Exception as e:
            rcode_name = "ERROR"
            g_rcode.labels(rcode=rcode_name).set(1)
            success = 0
        finally:
            overall_time = time.perf_counter() - overall_start
            g_dur.labels(phase="resolve").set(overall_time)
            g_success.set(success)

        # Prometheus response as text
        output = generate_latest(registry)
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE_LATEST)
        self.send_header("Content-Length", str(len(output)))
        self.end_headers()
        self.wfile.write(output)

def load_config(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if "modules" not in data or not isinstance(data["modules"], dict):
        raise RuntimeError("config: 'modules' map is required")
    if "listen_address" not in data:
        data["listen_address"] = ":9116"
    return data

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-config.file", dest="config_file", default="config.yml")
    args = parser.parse_args()
    cfg = load_config(args.config_file)

    host, port = "0.0.0.0", 9116
    addr = str(cfg.get("listen_address", ":9116")).strip()
    if addr.startswith(":"):
        port = int(addr[1:])
    else:
        host, port = addr.split(":")[0], int(addr.split(":")[1])

    class Srv(ThreadingHTTPServer):
        pass

    httpd = Srv((host, port), ProbeHandler)
    httpd.config = cfg
    print(f"dnsp_exporter listening on {host}:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()