from engine.ioc import (
    detect_iocs,
    MALICIOUS_DOMAINS,
    MALICIOUS_IPS,
    MALICIOUS_HASHES,
)

print("Domains:", MALICIOUS_DOMAINS)
print("IPs:", MALICIOUS_IPS)
print("Hashes:", MALICIOUS_HASHES)

events = [
    {
        "source": "dns",
        "timestamp": "2026-07-30T12:00:00Z",
        "ip": "192.168.1.10",
        "query": "evil.com",
        "user": "Administrator",
        "host": "WIN10-PC"
    }
]

print(detect_iocs(events))