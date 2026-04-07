"""
NetSentinel - Core Scanner Module
Handles port scanning via nmap and service enumeration
"""

import nmap
import socket
import json
import datetime
from typing import Optional


# Common ports and their known risk weights (used as features for ML)
KNOWN_RISKY_PORTS = {
    21: {"service": "FTP", "risk": "HIGH", "reason": "Plaintext auth, anon login possible"},
    22: {"service": "SSH", "risk": "MEDIUM", "reason": "Brute force target"},
    23: {"service": "Telnet", "risk": "CRITICAL", "reason": "Plaintext protocol, legacy"},
    25: {"service": "SMTP", "risk": "MEDIUM", "reason": "Open relay / spam abuse"},
    53: {"service": "DNS", "risk": "MEDIUM", "reason": "DNS amplification attacks"},
    80: {"service": "HTTP", "risk": "LOW", "reason": "Unencrypted web traffic"},
    110: {"service": "POP3", "risk": "HIGH", "reason": "Plaintext email retrieval"},
    135: {"service": "MSRPC", "risk": "HIGH", "reason": "Windows RPC exploitation"},
    139: {"service": "NetBIOS", "risk": "HIGH", "reason": "Information disclosure"},
    143: {"service": "IMAP", "risk": "MEDIUM", "reason": "Plaintext email access"},
    443: {"service": "HTTPS", "risk": "LOW", "reason": "Encrypted web traffic"},
    445: {"service": "SMB", "risk": "CRITICAL", "reason": "WannaCry / EternalBlue vector"},
    1433: {"service": "MSSQL", "risk": "HIGH", "reason": "Direct DB exposure"},
    1521: {"service": "Oracle DB", "risk": "HIGH", "reason": "Direct DB exposure"},
    3306: {"service": "MySQL", "risk": "HIGH", "reason": "Direct DB exposure"},
    3389: {"service": "RDP", "risk": "CRITICAL", "reason": "BlueKeep / brute force target"},
    5432: {"service": "PostgreSQL", "risk": "HIGH", "reason": "Direct DB exposure"},
    5900: {"service": "VNC", "risk": "CRITICAL", "reason": "Often no auth, remote desktop"},
    6379: {"service": "Redis", "risk": "CRITICAL", "reason": "No auth by default"},
    8080: {"service": "HTTP-Alt", "risk": "MEDIUM", "reason": "Dev server exposed"},
    8443: {"service": "HTTPS-Alt", "risk": "LOW", "reason": "Alt HTTPS port"},
    27017: {"service": "MongoDB", "risk": "CRITICAL", "reason": "No auth by default"},
}


class NetworkScanner:
    def __init__(self, timeout: int = 60):
        self.nm = nmap.PortScanner()
        self.timeout = timeout
        self.scan_time = None

    def validate_target(self, target: str) -> bool:
        """Validate that the target is a valid IP or hostname."""
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

    def scan(self, target: str, port_range: str = "1-1024", scan_type: str = "basic") -> dict:
        """
        Perform nmap scan on target.
        scan_type: 'basic' (SYN/TCP) or 'aggressive' (OS + version detection)
        """
        print(f"\n[*] Starting scan on: {target}")
        print(f"[*] Port range: {port_range}")
        print(f"[*] Scan type: {scan_type}\n")

        self.scan_time = datetime.datetime.now().isoformat()

        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        # Build nmap arguments
        if scan_type == "aggressive":
            args = f"-sV -O --open -T4"
        else:
            args = f"-sV --open -T3"

        try:
            self.nm.scan(hosts=target, ports=port_range, arguments=args)
        except nmap.PortScannerError as e:
            raise RuntimeError(f"Nmap error: {e}. Run as root/admin for best results.")

        return self._parse_results(target)

    def _parse_results(self, target: str) -> dict:
        """Parse raw nmap results into structured data."""
        results = {
            "target": target,
            "scan_time": self.scan_time,
            "hosts": []
        }

        for host in self.nm.all_hosts():
            host_data = {
                "ip": host,
                "hostname": self.nm[host].hostname() or "N/A",
                "state": self.nm[host].state(),
                "os_guess": self._get_os_guess(host),
                "open_ports": []
            }

            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in sorted(ports):
                    port_info = self.nm[host][proto][port]
                    if port_info["state"] == "open":
                        port_data = {
                            "port": port,
                            "protocol": proto,
                            "service": port_info.get("name", "unknown"),
                            "version": port_info.get("version", ""),
                            "product": port_info.get("product", ""),
                            "state": port_info["state"],
                            "known_risk": KNOWN_RISKY_PORTS.get(port, {}).get("risk", "UNKNOWN"),
                            "risk_reason": KNOWN_RISKY_PORTS.get(port, {}).get("reason", "Not in known database"),
                        }
                        host_data["open_ports"].append(port_data)

            results["hosts"].append(host_data)

        return results

    def _get_os_guess(self, host: str) -> str:
        """Extract best OS guess from nmap results."""
        try:
            os_matches = self.nm[host]["osmatch"]
            if os_matches:
                best = os_matches[0]
                return f"{best['name']} (accuracy: {best['accuracy']}%)"
        except (KeyError, IndexError):
            pass
        return "Unknown"

    def get_feature_vector(self, port_data: list) -> list:
        """
        Convert port scan results into ML feature vector.
        Features: [num_open_ports, has_critical_ports, has_db_ports,
                   has_remote_access, has_legacy_services, risk_score]
        """
        if not port_data:
            return [0, 0, 0, 0, 0, 0]

        critical_ports = {23, 445, 3389, 5900, 6379, 27017}
        db_ports = {1433, 1521, 3306, 5432, 27017, 6379}
        remote_access = {22, 23, 3389, 5900}
        legacy = {21, 23, 110, 139}

        open_set = {p["port"] for p in port_data}

        has_critical = int(bool(open_set & critical_ports))
        has_db = int(bool(open_set & db_ports))
        has_remote = int(bool(open_set & remote_access))
        has_legacy = int(bool(open_set & legacy))

        # Compute weighted risk score
        risk_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1}
        risk_score = sum(risk_map.get(p.get("known_risk", "UNKNOWN"), 1) for p in port_data)

        return [len(port_data), has_critical, has_db, has_remote, has_legacy, risk_score]
