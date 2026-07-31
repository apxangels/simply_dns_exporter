#!/usr/bin/env python3
import argparse

from murmurhash2 import murmurhash2

import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import dns.flags
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

def hash_fun(text: str) -> str:
    SEED = 228322
    return murmurhash2(text.encode("utf-8"), SEED)

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


def dns_query_generic_udp(name: str, rdtype, server: str, timeout: float):
    # EDNS0 + TCP fallback on truncation, needed for larger TXT (SPF/DMARC) answers
    q = dns.message.make_query(name, rdtype, use_edns=0, payload=4096)
    t0 = time.perf_counter()
    resp = dns.query.udp(q, server, timeout=timeout, ignore_unexpected=True)
    if resp.flags & dns.flags.TC:
        resp = dns.query.tcp(q, server, timeout=timeout)
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

def extract_records(resp: dns.message.Message, rdtype):
    records = []
    min_ttl = None
    for ans in resp.answer:
        if ans.rdtype == rdtype:
            records.extend(list(ans))
            if min_ttl is None or ans.ttl < min_ttl:
                min_ttl = ans.ttl
    return records, min_ttl

def rr_to_text(rr, rdtype) -> str:
    if rdtype == dns.rdatatype.NS:
        return str(rr.target).rstrip(".")
    if rdtype == dns.rdatatype.A:
        return rr.address
    if rdtype == dns.rdatatype.CNAME:
        return str(rr.target).rstrip(".")
    if rdtype == dns.rdatatype.MX:
        return f"{rr.preference} {str(rr.exchange).rstrip('.')}"
    if rdtype == dns.rdatatype.TXT:
        return b"".join(rr.strings).decode("utf-8", errors="replace")
    return str(rr)

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
        prober = str(mod.get("prober", "dns"))
        if prober not in ("dns", "dig"):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"only prober=dns or prober=dig is supported")
            return

        server_ip = str(mod.get("server", "")).strip()
        if not server_ip:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"module.server is required")
            return

        timeout_s = parse_duration(mod.get("timeout", "5s"))

        if prober == "dig":
            output = self._probe_dig(target, server_ip, timeout_s)
        else:
            output = self._probe_dns(mod, target, server_ip, timeout_s)

        if output is None:
            return  # error response already sent by the handler

        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE_LATEST)
        self.send_header("Content-Length", str(len(output)))
        self.end_headers()
        self.wfile.write(output)

    def _probe_dns(self, mod, target, server_ip, timeout_s):
        query_type = str(mod.get("query_type")).upper()
        if query_type not in ("A", "MX"):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"only query_type=A or query_type=MX is supported")
            return None

        # registry for one response
        registry = CollectorRegistry()
        # Gauges
        g_success = Gauge("dnsp_probe_success", "Probe success (1/0)", registry=registry)
        g_rcode = Gauge("dnsp_probe_dns_rcode", "DNS rcode", ["rcode"], registry=registry)
        g_dur = Gauge("dnsp_probe_dns_duration_seconds", "DNS probe durations", ["phase"], registry=registry)
        g_ttl = Gauge("dnsp_probe_ttl_seconds", "Min TTL for A records", registry=registry)
        if query_type == "A":
                g_ip = Gauge(
                    "dnsp_probe_ip_addr",
                    "Resolved A record",
                    ["domain", "ip_A_record"],
                    registry=registry,
                )
                g_ip_all = Gauge(
                    "dnsp_probe_ip_addr_all",
                    "All resolved A records in one label",
                    ["domain", "ip_A_record"],
                    registry=registry,
                )
                g_hash = Gauge(
                    "dnsp_probe_ip_addr_hash",
                    "murmurhash2 hash of sorted A records (duplicated per record)",
                    ["domain", "ip_A_record"],
                    registry=registry,
                )
                g_hash_all = Gauge(
                    "dnsp_probe_ip_addr_hash_all",
                    "murmurhash2 hash of sorted A records (all records in one label)",
                    ["domain", "ip_A_record"],
                    registry=registry,
                )
        if query_type == "MX":
            g_mx = Gauge(
                "dnsp_probe_mx_record", 
                "Resolved MX record", 
                ["domain", "exchange", "preference"], 
                registry=registry
            )

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
                        sorted_ips = sorted(set(ip_list))

                        for ip in sorted_ips:
                            g_ip.labels(domain=target, ip_A_record=ip).set(1)
                            # hash by each ip in a record
                            g_hash.labels(domain=target, ip_A_record=ip).set(hash_fun(ip))

                        if min_ttl is not None:
                            g_ttl.set(float(min_ttl))

                        # hash by concated ips
                        hash_input = ",".join(sorted_ips)
                        hash_val = hash_fun(hash_input)

                        g_ip_all.labels(domain=target, ip_A_record=",".join(sorted_ips)).set(1)
                        g_hash_all.labels(domain=target, ip_A_record=",".join(sorted_ips)).set(hash_val)

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

        return generate_latest(registry)

    def _probe_dig(self, target, server_ip, timeout_s):
        registry = CollectorRegistry()
        g_success = Gauge("dnsp_probe_success", "Probe success (1/0)", registry=registry)
        g_rcode = Gauge(
            "dnsp_probe_dns_rcode",
            "DNS rcode per queried record",
            ["record_name", "record_type", "rcode"],
            registry=registry,
        )
        g_dur = Gauge("dnsp_probe_dns_duration_seconds", "DNS probe durations", ["phase"], registry=registry)
        g_ttl = Gauge(
            "dnsp_probe_dig_ttl_seconds",
            "Min TTL for a queried record",
            ["record_name", "record_type"],
            registry=registry,
        )
        g_record = Gauge(
            "dnsp_probe_dig_record",
            "Resolved dig record (existence flag)",
            ["record_name", "record_type", "value"],
            registry=registry,
        )
        g_record_hash = Gauge(
            "dnsp_probe_dig_record_hash",
            "murmurhash2 hash of a single record value",
            ["record_name", "record_type", "value"],
            registry=registry,
        )
        g_record_hash_all = Gauge(
            "dnsp_probe_dig_record_hash_all",
            "murmurhash2 hash of all sorted values for one record_name/record_type",
            ["record_name", "record_type"],
            registry=registry,
        )
        g_domain_hash = Gauge(
            "dnsp_probe_dig_domain_hash",
            "murmurhash2 hash of every resolved value for the domain, use to detect any DNS change",
            ["domain"],
            registry=registry,
        )

        # apex: NS / A / CNAME / MX / TXT, plus the well-known autodiscover and DKIM selector names
        queries = [
            (target, (dns.rdatatype.NS, dns.rdatatype.A, dns.rdatatype.CNAME, dns.rdatatype.MX, dns.rdatatype.TXT)),
            (f"autodiscover.{target}", (dns.rdatatype.A, dns.rdatatype.CNAME, dns.rdatatype.TXT)),
            (f"selector1._domainkey.{target}", (dns.rdatatype.CNAME, dns.rdatatype.TXT)),
            (f"selector2._domainkey.{target}", (dns.rdatatype.CNAME, dns.rdatatype.TXT)),
        ]

        overall_start = time.perf_counter()
        success = 0
        domain_parts = []

        try:
            connect_time = tcp_connect_check(server_ip, 53, timeout_s)
            g_dur.labels(phase="connect").set(connect_time)

            for record_name, rdtypes in queries:
                for rdtype in rdtypes:
                    type_name = dns.rdatatype.to_text(rdtype)
                    try:
                        resp, _req_time = dns_query_generic_udp(record_name, rdtype, server_ip, timeout_s)
                    except socket.timeout:
                        g_rcode.labels(record_name=record_name, record_type=type_name, rcode="TIMEOUT").set(1)
                        continue
                    except Exception:
                        g_rcode.labels(record_name=record_name, record_type=type_name, rcode="ERROR").set(1)
                        continue

                    rcode_val = resp.rcode()
                    rcode_name = dns.rcode.to_text(rcode_val)
                    g_rcode.labels(record_name=record_name, record_type=type_name, rcode=rcode_name).set(1)

                    if rcode_val != dns.rcode.NOERROR:
                        continue

                    records, min_ttl = extract_records(resp, rdtype)
                    if not records:
                        continue

                    values = sorted(set(rr_to_text(rr, rdtype) for rr in records))
                    for v in values:
                        g_record.labels(record_name=record_name, record_type=type_name, value=v).set(1)
                        g_record_hash.labels(record_name=record_name, record_type=type_name, value=v).set(hash_fun(v))

                    joined = ",".join(values)
                    g_record_hash_all.labels(record_name=record_name, record_type=type_name).set(hash_fun(joined))

                    if min_ttl is not None:
                        g_ttl.labels(record_name=record_name, record_type=type_name).set(float(min_ttl))

                    domain_parts.append(f"{record_name}|{type_name}|{joined}")
                    success = 1

            if domain_parts:
                g_domain_hash.labels(domain=target).set(hash_fun("\n".join(sorted(domain_parts))))

        except socket.timeout:
            g_rcode.labels(record_name=target, record_type="ANY", rcode="TIMEOUT").set(1)
            success = 0
        except Exception:
            g_rcode.labels(record_name=target, record_type="ANY", rcode="ERROR").set(1)
            success = 0
        finally:
            overall_time = time.perf_counter() - overall_start
            g_dur.labels(phase="resolve").set(overall_time)
            g_success.set(success)

        return generate_latest(registry)

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