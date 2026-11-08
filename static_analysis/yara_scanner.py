"""YARA-based static signature scanner for cryptominer and packed loader detection."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

try:
    import yara
    YARA_AVAILABLE = True
except Exception:  # pragma: no cover
    yara = None
    YARA_AVAILABLE = False


_YARA_RULES_SOURCE = r"""
rule CryptoMiner_XMRig_Signature
{
    meta:
        description = "Detects XMRig and RandomX CPU cryptocurrency miners"
        category = "miner"
        severity = "critical"
    strings:
        $id1 = "xmrig" nocase ascii wide
        $id2 = "randomx_init_cache" ascii wide
        $id3 = "randomx_create_vm" ascii wide
        $id4 = "--donate-level" ascii wide
        $id5 = "--cpu-max-threads-pct" ascii wide
        $id6 = "--pause-on-active" ascii wide
        $id7 = "rx/0" ascii wide
        $id8 = "cryptonight" nocase ascii wide
        $id9 = "moneroocean" nocase ascii wide
        $id10 = "supportxmr" nocase ascii wide
        $id11 = "minexmr" nocase ascii wide
        $id12 = "stratum+tcp://" nocase ascii wide
        $id13 = "stratum+ssl://" nocase ascii wide
    condition:
        ($id2 or $id3) or
        ($id1 and 1 of ($id4, $id5, $id6, $id7, $id8, $id9, $id10, $id11, $id12, $id13)) or
        2 of ($id4, $id5, $id6, $id7, $id12, $id13)
}

rule CryptoMiner_Stratum_Protocol
{
    meta:
        description = "Detects JSON-RPC Stratum pool protocol methods"
        category = "miner"
        severity = "critical"
    strings:
        $m1 = "mining.subscribe" ascii wide
        $m2 = "mining.authorize" ascii wide
        $m3 = "mining.submit" ascii wide
        $m4 = "mining.notify" ascii wide
        $m5 = "mining.set_difficulty" ascii wide
        $m6 = "mining.extranonce" ascii wide
    condition:
        2 of ($m1, $m2, $m3, $m4, $m5, $m6)
}

rule CryptoMiner_Wallet_And_Pool_Config
{
    meta:
        description = "Detects embedded Stratum pool URLs or Monero wallets paired with miner keywords"
        category = "miner"
        severity = "high"
    strings:
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii wide
        $stratum = /stratum\+(tcp|ssl|udp):\/\/[A-Za-z0-9._-]+:[0-9]{2,5}/ nocase ascii wide
        $k1 = "monero" nocase ascii wide
        $k2 = "randomx" nocase ascii wide
        $k3 = "ethash" nocase ascii wide
        $k4 = "kawpow" nocase ascii wide
        $k5 = "\"pools\"" ascii wide
        $k6 = "\"algo\"" ascii wide
        $k7 = "donate-level" ascii wide
    condition:
        ($stratum and 1 of ($k1, $k2, $k3, $k4, $k5, $k6, $k7, $xmr)) or
        ($xmr and 1 of ($k1, $k2, $k5, $k6, $k7, $stratum))
}

rule CryptoMiner_GPU_MultiMiner
{
    meta:
        description = "Detects GPU cryptomining clients (Ethminer, lolMiner, NBMiner, T-Rex, GMiner)"
        category = "miner"
        severity = "high"
    strings:
        $g1 = "ethminer" nocase ascii wide
        $g2 = "lolminer" nocase ascii wide
        $g3 = "nbminer" nocase ascii wide
        $g4 = "phoenixminer" nocase ascii wide
        $g5 = "teamredminer" nocase ascii wide
        $g6 = "daggerhashimoto" nocase ascii wide
        $g7 = "kawpow" nocase ascii wide
        $g8 = "--cuda-devices" ascii wide
        $g9 = "--opencl-platform" ascii wide
        $g10 = "stratum" nocase ascii wide
    condition:
        1 of ($g1, $g2, $g3, $g4, $g5) and 1 of ($g6, $g7, $g8, $g9, $g10)
}

rule Packer_UPX_Sections
{
    meta:
        description = "Detects UPX-packed PE sections commonly used to obfuscate miner binaries"
        category = "packer"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($upx0, $upx1, $upx2)
}
"""

_SEVERITY_RANK = {"none": 0, "medium": 1, "high": 2, "critical": 3}


class YaraMinerScanner:
    """Thread-safe bounded-read YARA scanner for cryptojacking executables."""

    DEFAULT_MAX_SCAN_BYTES = 32 * 1024 * 1024

    def __init__(self, max_scan_bytes: Optional[int] = DEFAULT_MAX_SCAN_BYTES, rules_dir: Optional[str] = None):
        self.max_scan_bytes = max_scan_bytes
        self._rules = None
        if not YARA_AVAILABLE:
            return

        sources: Dict[str, str] = {"builtin_miners": _YARA_RULES_SOURCE}
        if rules_dir and os.path.isdir(rules_dir):
            for fname in sorted(os.listdir(rules_dir)):
                if fname.endswith((".yar", ".yara")):
                    fpath = os.path.join(rules_dir, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            sources[fname] = f.read()
                    except OSError:
                        continue
        try:
            self._rules = yara.compile(sources=sources)
        except Exception:
            self._rules = None

    def _read_bounded_bytes(self, file_path: str) -> bytes:
        file_size = os.path.getsize(file_path)
        limit = self.max_scan_bytes
        if limit is None or file_size <= limit:
            with open(file_path, "rb") as f:
                return f.read()

        # Read both head (PE headers, imports, embedded strings) and tail (appended configs/overlays).
        half = max(1, limit // 2)
        with open(file_path, "rb") as f:
            head = f.read(half)
            f.seek(max(half, file_size - (limit - len(head))))
            tail = f.read(limit - len(head))
        return head + b"\x00" + tail

    def scan_bytes(self, data: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "yara_matched": False,
            "miner_rules": [],
            "packed_rules": [],
            "all_rules": [],
            "is_packed": False,
            "max_severity": "none",
            "scan_error": None,
        }
        if not self._rules or not data:
            return result

        try:
            matches = self._rules.match(data=data, timeout=5)
        except Exception as exc:
            result["scan_error"] = str(exc)
            return result

        highest = "none"
        for match in matches:
            rule_name = str(getattr(match, "rule", ""))
            meta = getattr(match, "meta", {}) or {}
            category = str(meta.get("category") or "miner").lower()
            severity = str(meta.get("severity") or "high").lower()
            result["all_rules"].append(rule_name)
            if category == "packer":
                result["is_packed"] = True
                result["packed_rules"].append(rule_name)
            else:
                result["miner_rules"].append(rule_name)
                if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(highest, 0):
                    highest = severity

        result["yara_matched"] = len(result["miner_rules"]) > 0
        result["max_severity"] = highest if result["yara_matched"] else ("medium" if result["is_packed"] else "none")
        return result

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        if not file_path or not os.path.isfile(file_path):
            return {
                "yara_matched": False,
                "miner_rules": [],
                "packed_rules": [],
                "all_rules": [],
                "is_packed": False,
                "max_severity": "none",
                "scan_error": "file_not_found",
            }
        try:
            data = self._read_bounded_bytes(file_path)
        except Exception as exc:
            return {
                "yara_matched": False,
                "miner_rules": [],
                "packed_rules": [],
                "all_rules": [],
                "is_packed": False,
                "max_severity": "none",
                "scan_error": str(exc),
            }
        return self.scan_bytes(data)

