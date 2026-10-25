# Defensive Cybersecurity Rules & Guardrails

1. **Defensive Scope Exclusivity**:
   - This project strictly performs defensive detection and traffic analysis.
   - Do not implement offensive penetration testing scripts, denial-of-service attack generators, SYN flooders, UDP packet cannons, or amplification tools.

2. **Offline Safety**:
   - Only process saved capture files (`.pcap`, `.pcapng`, `.csv`).
   - Do not configure promiscuous network interface listeners or raw sockets that require root/administrator privileges in development.

3. **Untrusted Data Handling**:
   - PCAP files and network telemetry must be treated as untrusted user input.
   - Do not deserialize untrusted data with `pickle` or `yaml.load` (use `yaml.safe_load`).
   - Prevent command injection: never execute shell processes based on strings extracted from packet headers or payloads.

4. **Privacy & Redaction**:
   - Never print raw payload contents containing sensitive plaintext protocols (e.g., HTTP basic auth, telnet, FTP).
   - In logs and alert sinks, log only structural metadata (IP addresses, ports, protocol names, packet rates, byte counts).
