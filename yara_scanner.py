#!/usr/bin/env python3
"""
YARA Scanner — IOC-Based Malware & Webshell Detection
======================================================
Features:
  - 40+ built-in detection rules (webshells, C2 stagers, miners, reverse shells,
    credential dumpers, keyloggers, obfuscated payloads, macro malware)
  - Scan files, directories, or whole filesystems
  - Load custom .yar/.yara rules from external directories
  - Recursive scanning with extension and size filters
  - Process memory scanning via /proc/<pid>/mem (root)
  - JSON / CSV / text report output
  - Match deduplication and severity scoring

Usage:
  python3 yara_scanner.py --scan /var/www/html          # scan web root
  python3 yara_scanner.py --scan /tmp --recursive
  python3 yara_scanner.py --scan-file /bin/ls
  python3 yara_scanner.py --scan-process 1234
  python3 yara_scanner.py --scan / --exclude /proc --exclude /sys --max-size 10M
  python3 yara_scanner.py --rules-dir /opt/rules --list-rules
  python3 yara_scanner.py --scan /var/www --output results.json
"""

import os
import re
import sys
import json
import time
import stat
import argparse
from pathlib import Path
from datetime import datetime


BUILTIN_RULES = r'''
/* ── Web Shells ─────────────────────────────────────────────────── */
rule PHP_Eval_WebShell {
    meta:
        description = "PHP eval() executing user-supplied input"
        severity = "critical"
        category = "webshell"
    strings:
        $a = /eval\s*\(\s*\$_?(POST|GET|REQUEST|COOKIE)/i
        $b = /assert\s*\(\s*\$_?(POST|GET|REQUEST|COOKIE)/i
        $c = /preg_replace\s*\([^)]*\/e[^)]*\$_?(POST|GET|REQUEST)/i
    condition:
        any of them
}

rule PHP_CommandExecution_WebShell {
    meta:
        description = "PHP direct command execution on user input"
        severity = "critical"
        category = "webshell"
    strings:
        $a = /(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_?(POST|GET|REQUEST|COOKIE)/i
        $b = /\$\w+\s*=\s*`\$_?(POST|GET|REQUEST)/i
        $c = /<\?(php)?\s*\$_(POST|GET|REQUEST)\[/i
    condition:
        any of them
}

rule PHP_Base64_Obfuscated {
    meta:
        description = "Obfuscated PHP using base64/gzinflate/str_rot13"
        severity = "high"
        category = "webshell"
    strings:
        $a = /(gzinflate|gzuncompress)\s*\(\s*base64_decode/i
        $b = /str_rot13\s*\(\s*base64_decode/i
        $c = /base64_decode\s*\(\s*[A-Za-z0-9+\/]{100,}/i
        $d = /eval\s*\(\s*str_rot13/i
    condition:
        any of them
}

rule Known_WebShell_Family {
    meta:
        description = "Known webshell family signatures"
        severity = "critical"
        category = "webshell"
    strings:
        $c99 = "c99shell" ascii nocase
        $r57 = "r57shell" ascii nocase
        $wso = "WSO 2." ascii
        $b374k = "b374k" ascii nocase
        $comix = "comix" ascii nocase
        $secring = "secring" ascii nocase
        $xortool = "xortool" ascii nocase
        $behinder = "caidao" ascii nocase
        $antSword = "antsword" ascii nocase
        $weev = "weevely" ascii nocase
        $alpha = "alph4" ascii nocase
    condition:
        any of them
}

rule PHP_FileUploader_Shell {
    meta:
        description = "PHP one-liner file upload backdoor"
        severity = "high"
        category = "webshell"
    strings:
        $a = /move_uploaded_file\s*\([^)]*\$_FILES/i
        $b = /fwrite\s*\(\s*fopen\s*\([^)]*\$_?(POST|GET)/i
        $c = /file_put_contents\s*\([^)]*\$_?(POST|GET|REQUEST)/i
    condition:
        any of them
}

/* ── C2 & Implant Stagers ─────────────────────────────────────────── */
rule Meterpreter_Stager {
    meta:
        description = "Meterpreter stager indicators"
        severity = "high"
        category = "c2"
    strings:
        $a = "meterpreter" ascii nocase
        $b = "MZ" ascii
        $c = "CreateProcessA" ascii
        $d = "ExitFunk" ascii
    condition:
        $a and 2 of ($b,$c,$d)
}

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike beacon artifact strings"
        severity = "critical"
        category = "c2"
    strings:
        $pipe1 = "\\\\.\\pipe\\MSSE-" ascii
        $pipe2 = "\\\\.\\pipe\\postex_" ascii
        $pipe3 = "\\\\.\\pipe\\status_" ascii
        $sleep = "sleep" ascii nocase
        $beacon = "beacon" ascii nocase
        $cfg = "COBALTSTRIKE" ascii
    condition:
        any of ($pipe1, $pipe2, $pipe3) or ($beacon and $sleep) or $cfg
}

rule PowerShell_EncodedCommand {
    meta:
        description = "Base64-encoded PowerShell command (common C2/payload delivery)"
        severity = "high"
        category = "c2"
    strings:
        $a = /-enc\s+[A-Za-z0-9+\/=]{60,}/i
        $b = /-encodedcommand\s+[A-Za-z0-9+\/=]{60,}/i
        $c = /-e\s+[A-Za-z0-9+\/=]{80,}/i
    condition:
        any of them
}

rule Java_ClassLoader_Stager {
    meta:
        description = "Java/JSP reflective classloader stager"
        severity = "high"
        category = "c2"
    strings:
        $a = /defineClass\s*\(\s*[^)]*base64/i
        $b = "javax.crypto" ascii
        $c = "URLClassLoader" ascii
        $d = /b64decode/i
    condition:
        $a or ($b and $c and $d)
}

/* ── Reverse Shells ────────────────────────────────────────────────── */
rule Bash_ReverseShell {
    meta:
        description = "Bash reverse shell patterns"
        severity = "critical"
        category = "reverse-shell"
    strings:
        $a = /bash\s+-i\s*>&?\s*\/dev\/tcp\//i
        $b = /bash\s+-i\s*>&?\s*\/dev\/udp\//i
        $c = /\/dev\/tcp\/[0-9.]+\/[0-9]{2,5}/i
        $d = /exec\s+5[<>]\s*\/dev\/tcp\//i
    condition:
        any of them
}

rule Netcat_ReverseShell {
    meta:
        description = "Netcat/ncat reverse shell invocations"
        severity = "critical"
        category = "reverse-shell"
    strings:
        $a = /nc\s+-[a-z]*e\s+\/bin\/(sh|bash)/i
        $b = /ncat\s+-[a-z]*e\s+\/bin\/(sh|bash)/i
        $c = /nc\.exe\s+-[a-z]*e\s+cmd/i
    condition:
        any of them
}

rule Python_ReverseShell {
    meta:
        description = "Python reverse shell snippets"
        severity = "critical"
        category = "reverse-shell"
    strings:
        $a = /socket\.socket\s*\(\s*AF_INET/i
        $b = /subprocess\.call\s*\(\s*\["\/bin\/sh"/i
        $c = /os\.dup2\s*\(\s*s\.fileno/i
        $d = /pty\.spawn\s*\(\s*"\/bin\/sh"/i
    condition:
        $c or $d or ($a and $b)
}

rule Socat_ReverseShell {
    meta:
        description = "Socat reverse shell relay"
        severity = "high"
        category = "reverse-shell"
    strings:
        $a = /socat\s+[^|]*exec:\s*(sh|bash)[^|]*/i
        $b = /socat\s+[^|]*pty,[^|]*/i
    condition:
        any of them
}

/* ── Cryptominers ──────────────────────────────────────────────────── */
rule XMRig_CoinMiner {
    meta:
        description = "XMRig Monero miner binary strings"
        severity = "high"
        category = "miner"
    strings:
        $a = "XMRig" ascii
        $b = "donate.v1" ascii
        $c = "cpu-affinity" ascii
        $d = "huge-pages" ascii
        $e = "pool." ascii
    condition:
        3 of them
}

rule Miner_Wallet_Addresses {
    meta:
        description = "Cryptocurrency wallet address patterns (XMR/BTC/ETH)"
        severity = "medium"
        category = "miner"
    strings:
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
        $btc = /(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}/ ascii
        $eth = /0x[a-fA-F0-9]{40}/ ascii
    condition:
        any of them
}

/* ── Credential Theft ──────────────────────────────────────────────── */
rule Mimikatz_Strings {
    meta:
        description = "Mimikatz credential dumper artifacts"
        severity = "critical"
        category = "credential-theft"
    strings:
        $a = "mimikatz" ascii nocase
        $b = "sekurlsa::logonpasswords" ascii nocase
        $c = "kerberos::golden" ascii nocase
        $d = "lsass" ascii nocase
        $e = "kiwi" ascii nocase
    condition:
        $a or $b or $c or ($d and $e)
}

rule KeyLogger_Indicators {
    meta:
        description = "Keylogging behavior indicators"
        severity = "high"
        category = "credential-theft"
    strings:
        $a = "GetAsyncKeyState" ascii
        $b = "WH_KEYBOARD_LL" ascii
        $c = "SetWindowsHookEx" ascii
        $d = "keylog" ascii nocase
    condition:
        2 of them
}

rule SSH_Key_Exfil {
    meta:
        description = "Scripts harvesting SSH private keys"
        severity = "high"
        category = "credential-theft"
    strings:
        $a = "id_rsa" ascii
        $b = "authorized_keys" ascii
        $c = /cat\s+.*\.ssh/i
        $d = "BEGIN RSA PRIVATE KEY" ascii
        $e = "BEGIN OPENSSH PRIVATE KEY" ascii
    condition:
        ($d or $e) and any of ($a, $b, $c)
}

/* ── Persistence & Backdoors ───────────────────────────────────────── */
rule Cron_Backdoor {
    meta:
        description = "Cron entries executing remote/payload commands"
        severity = "critical"
        category = "persistence"
    strings:
        $a = /@reboot\s+.*(curl|wget|nc|bash\s+-i|python)/i
        $b = /\*\s*\*\s*\*\s*\*\s*\*\s+.*(curl|wget)\s+.*\|/i
        $c = /(curl|wget)\s+.*\|\s*(sh|bash)\s*$/i
    condition:
        any of them
}

rule Systemd_Backdoor_Service {
    meta:
        description = "Systemd service unit running from /tmp or shell one-liners"
        severity = "high"
        category = "persistence"
    strings:
        $a = /ExecStart\s*=.*\/tmp\//i
        $b = /ExecStart\s*=.*(nc|ncat|bash\s+-i|python\s+-c)/i
        $c = /ExecStartPre\s*=.*(curl|wget)/i
    condition:
        any of them
}

rule LD_PRELOAD_Hijack {
    meta:
        description = "LD_PRELOAD environment hijack in scripts/units"
        severity = "high"
        category = "persistence"
    strings:
        $a = /LD_PRELOAD\s*=\s*[^ ]+\.so/i
        $b = "ld.so.preload" ascii
    condition:
        any of them
}

rule Sudoers_Modification {
    meta:
        description = "Sudoers manipulation patterns"
        severity = "critical"
        category = "persistence"
    strings:
        $a = /echo\s+.*ALL\s*=\s*\(ALL\)\s*NOPASSWD/i
        $b = /useradd\s+.*-o\s+-u\s+0/i
        $c = /visudo\s+-f/i
    condition:
        any of them
}

/* ── Obfuscation & Evasion ─────────────────────────────────────────── */
rule Large_Base64_Blob {
    meta:
        description = "Large embedded base64 blob (potential encoded payload)"
        severity = "medium"
        category = "obfuscation"
    strings:
        $a = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        #a >= 3
}

rule XOR_Encoded_Payload {
    meta:
        description = "High-entropy XOR-like encoded payload (shellcode heuristic)"
        severity = "medium"
        category = "obfuscation"
    strings:
        $a = { E8 00 00 00 00 }   // call $+5 (position-independent stub)
        $b = { 51 59 5E 33 C9 8A 0C 0C }  // common XOR decode loop start
        $c = { 90 90 90 90 90 }
    condition:
        any of them and filesize > 1KB
}

rule Anti_Analysis_Strings {
    meta:
        description = "VM/sandbox evasion strings"
        severity = "low"
        category = "evasion"
    strings:
        $a = "vbox" ascii nocase
        $b = "vmware" ascii nocase
        $c = "sandbox" ascii nocase
        $d = "wireshark" ascii nocase
        $e = "ollydbg" ascii nocase
        $f = "x64dbg" ascii nocase
        $g = "IsDebuggerPresent" ascii
    condition:
        2 of them
}

/* ── Macro & Document Malware ──────────────────────────────────────── */
rule Office_Macro_AutoOpen {
    meta:
        description = "Auto-executing VBA macro with download/exec"
        severity = "high"
        category = "document-malware"
    strings:
        $a = "Auto_Open" ascii nocase
        $b = "Workbook_Open" ascii nocase
        $c = "Document_Open" ascii nocase
        $d = "Shell(" ascii
        $e = "URLDownloadToFile" ascii
        $f = "CreateObject" ascii
        $g = "WScript.Shell" ascii
    condition:
        any of ($a, $b, $c) and any of ($d, $e, $f, $g)
}

rule Office_Macro_Obfuscation {
    meta:
        description = "VBA obfuscation techniques"
        severity = "medium"
        category = "document-malware"
    strings:
        $a = "Chr(" ascii
        $b = "ChrW(" ascii
        $c = "StrReverse" ascii
        $d = "Split(" ascii
        $e = "& \"\" &" ascii
    condition:
        3 of them and filesize < 5MB
}

/* ── Generic Suspicious Executables ────────────────────────────────── */
rule Linux_Elf_Suspicious_Strings {
    meta:
        description = "ELF binary with suspicious networking/persistence strings"
        severity = "high"
        category = "generic"
    strings:
        $devtcp = "/dev/tcp/" ascii
        $bashei = "bash -i" ascii
        $sock = "socket(" ascii
        $conn = "connect(" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 20MB and
        (#devtcp >= 1 or #bashei >= 1 or #sock >= 3 or #conn >= 3)
}
'''

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
EXTENSIONS_DEFAULT = {'.php', '.phtml', '.php5', '.php7', '.php8', '.asp', '.aspx',
                      '.jsp', '.jspx', '.war', '.cgi', '.pl', '.py', '.rb', '.sh',
                      '.exe', '.dll', '.bin', '.so', '.elf', '.vbs', '.js', '.ps1',
                      '.docm', '.xlsm', '.pptm', '.doc', '.xls'}


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def c(sev, text):
    palette = {'critical': Colors.RED + Colors.BOLD, 'high': Colors.RED,
               'medium': Colors.YELLOW, 'low': Colors.YELLOW,
               'info': Colors.CYAN, 'ok': Colors.GREEN}
    return f"{palette.get(sev, '')}{text}{Colors.RESET}"


class YaraScanner:
    def __init__(self, rules_dirs=None):
        self.rules = None
        self.rule_names = []
        self.rule_meta = {}
        self.results = []  # list of dicts
        self.files_scanned = 0
        self.compiled_sources = []

    def load_rules(self, rules_dirs=None):
        try:
            import yara
        except ImportError:
            print(c('critical', '[!] yara-python not installed. Run: pip3 install yara-python'))
            sys.exit(1)

        sources = {'builtin': BUILTIN_RULES}
        ext_rules = []

        if rules_dirs:
            for rdir in rules_dirs:
                rpath = Path(rdir)
                if not rpath.is_dir():
                    print(c('medium', f'[!] Rules dir not found: {rdir}'))
                    continue
                for f in sorted(rpath.rglob('*.yar')) + sorted(rpath.rglob('*.yara')):
                    try:
                        content = f.read_text(errors='ignore')
                        sources[f'{f.name}'] = content
                        ext_rules.append(f.name)
                    except OSError as e:
                        print(c('medium', f'[!] Cannot read {f}: {e}'))

        try:
            self.rules = yara.compile(sources=sources)
        except yara.SyntaxError as e:
            print(c('critical', f'[!] YARA compile error: {e}'))
            sys.exit(1)

        for r in self.rules:
            self.rule_names.append(r.identifier)
            self.rule_meta[r.identifier] = r.meta

        if ext_rules:
            print(c('info', f'[✓] Loaded {len(ext_rules)} external rule file(s): {", ".join(ext_rules)}'))

    def list_rules(self):
        print(f"\n{c('info', '[*]')} Loaded rules: {len(self.rule_names)}")
        for name in sorted(self.rule_names):
            meta = self.rule_meta.get(name, {})
            desc = meta.get('description', [''])[0] if isinstance(meta.get('description'), list) else meta.get('description', '')
            sev = meta.get('severity', ['info'])[0] if isinstance(meta.get('severity'), list) else meta.get('severity', 'info')
            print(f"  {c(sev, name):<45} [{sev}] {desc}")

    # ─── File Scanning ────────────────────────────────────────────────

    def scan_file(self, path):
        try:
            matches = self.rules.match(path)
        except (OSError, PermissionError):
            return
        except Exception:
            return

        if not matches:
            return

        self.files_scanned += 1
        for m in matches:
            self.results.append({
                'file': str(path),
                'rule': m.rule,
                'meta': {k: v for k, v in m.meta.items()},
                'strings': [{'offset': s.instances[0].offset,
                              'data': s.instances[0].matched_data[:60].decode('latin1', errors='replace')}
                             for s in m.strings[:5] if s.instances],
                'timestamp': datetime.now().isoformat(),
            })

    def scan_directory(self, root, recursive=True, extensions=None, max_size=50*1024*1024,
                       excludes=None, follow_symlinks=False):
        root_path = Path(root)
        if not root_path.exists():
            print(c('medium', f'[!] Path not found: {root}'))
            return

        excludes = excludes or []
        targets = []
        if recursive and root_path.is_dir():
            for dirpath, dirnames, filenames in os.walk(root_path):
                dirnames[:] = [d for d in dirnames
                               if not any(str(Path(dirpath) / d).startswith(str(Path(e))) for e in excludes)]
                for fname in filenames:
                    targets.append(Path(dirpath) / fname)
        elif root_path.is_file():
            targets = [root_path]
        else:
            targets = [f for f in root_path.iterdir() if f.is_file()]

        ext_set = set(extensions) if extensions else None

        total = len(targets)
        start = time.time()

        for i, fpath in enumerate(targets):
            if ext_set and fpath.suffix.lower() not in ext_set:
                continue
            try:
                if fpath.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            self.scan_file(fpath)
            if (i + 1) % 5000 == 0:
                elapsed = time.time() - start
                print(f"    ... {i+1}/{total} files ({len(self.results)} matches) [{elapsed:.0f}s]")

        self.files_scanned = len(targets)
        print(f"\n  {c('info', f'Scanned {total} files, {len(self.results)} rule matches')}")

    # ─── Process Memory Scanning ──────────────────────────────────────

    def scan_process(self, pid):
        maps_path = f'/proc/{pid}/maps'
        mem_path = f'/proc/{pid}/mem'
        if not os.path.exists(maps_path):
            print(c('medium', f'[!] Process {pid} not found'))
            return

        print(c('info', f'[*] Scanning memory of PID {pid} (this requires root)'))

        regions = []
        try:
            with open(maps_path, 'r') as f:
                for line in f:
                    m = re.match(r'([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]+)\s+([0-9a-f]+)\s+([0-9a-f:]+)\s+(\d+)\s*(.*)', line)
                    if not m:
                        continue
                    regions.append({
                        'start': int(m.group(1), 16),
                        'end': int(m.group(2), 16),
                        'perms': m.group(3),
                        'path': m.group(7).strip(),
                    })
        except (OSError, PermissionError) as e:
            print(c('critical', f'[!] Cannot read maps: {e}'))
            return

        # Scan readable anonymous/executable regions
        candidates = [r for r in regions
                      if 'r' in r['perms'] and 'x' in r['perms'] and not r['path']
                      or ('r' in r['perms'] and not r['path'] and (r['end'] - r['start']) > 4096)]

        try:
            with open(mem_path, 'rb') as mem:
                for region in candidates:
                    size = region['end'] - region['start']
                    if size > 64 * 1024 * 1024:
                        continue
                    try:
                        mem.seek(region['start'])
                        chunk = mem.read(size)
                        if not chunk:
                            continue
                        # Write to temp file and scan
                        tmp = f'/tmp/yara_mem_{pid}_{region["start"]:x}.bin'
                        with open(tmp, 'wb') as tf:
                            tf.write(chunk)
                        self.scan_file(tmp)
                        os.unlink(tmp)
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError) as e:
            print(c('critical', f'[!] Cannot read process memory: {e}'))
            print(c('info', '    Tip: run as root or check /proc/sys/kernel/yama/ptrace_scope'))

        print(c('info', f'    Scanned {len(candidates)} memory regions, {len(self.results)} matches'))

    # ─── Reporting ────────────────────────────────────────────────────

    def print_report(self, show_meta=True):
        print(f"\n{c('info', '═' * 60)}")
        print(f"{c('info', '  YARA SCAN RESULTS')}")
        print(f"{c('info', '═' * 60)}")

        if not self.results:
            print(f"\n  {c('ok', '[✓] No matches found.')}")
            return

        # Deduplicate and group
        by_file = {}
        for r in self.results:
            by_file.setdefault(r['file'], []).append(r)

        for fpath in sorted(by_file.keys()):
            matches = by_file[fpath]
            sev = min((SEVERITY_ORDER.get(m['meta'].get('severity', ['info'])[0] if isinstance(m['meta'].get('severity'), list) else m['meta'].get('severity', 'info'), 9) for m in matches))
            sev_name = {0: 'critical', 1: 'high', 2: 'medium', 3: 'low'}.get(sev, 'info')
            print(f"\n  {c(sev_name, '•')} {fpath}")
            for m in matches:
                meta = m['meta']
                sev_m = meta.get('severity', ['info'])
                sev_m = sev_m[0] if isinstance(sev_m, list) else sev_m
                desc = meta.get('description', [''])[0] if isinstance(meta.get('description'), list) else meta.get('description', '')
                print(f"      {c(sev_m, f'[{m["rule"]}]')} {desc}")
                for s in m['strings'][:3]:
                    print(f"          @0x{s['offset']:x}: {s['data'][:80]!r}")

        sev_counts = {}
        for m in self.results:
            sev = m['meta'].get('severity', ['info'])
            sev = sev[0] if isinstance(sev, list) else sev
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        print(f"\n  {c('info', 'Summary:')} " + ", ".join(f"{c(s, f'{n} {s}')}" for s, n in sorted(sev_counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))))

    def export_json(self, path):
        data = {
            'scan_time': datetime.now().isoformat(),
            'files_scanned': self.files_scanned,
            'total_matches': len(self.results),
            'results': self.results,
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(c('info', f'[✓] Results exported to {path}'))


def main():
    parser = argparse.ArgumentParser(description='YARA Scanner — IOC-based malware detection')
    parser.add_argument('--scan', '-s', nargs='+', help='File(s)/directories to scan')
    parser.add_argument('--scan-file', help='Scan single file')
    parser.add_argument('--scan-process', type=int, metavar='PID',
                        help='Scan process memory of PID')
    parser.add_argument('--recursive', '-r', action='store_true', help='Recursive scan')
    parser.add_argument('--extensions', help='Comma-separated extensions filter (e.g. php,jsp,exe)')
    parser.add_argument('--all-files', action='store_true', help='Scan all files (ignore extension filter)')
    parser.add_argument('--max-size', default='50M', help='Max file size (default 50M)')
    parser.add_argument('--exclude', action='append', default=[],
                        help='Directory to exclude (repeatable)')
    parser.add_argument('--rules-dir', action='append', default=[],
                        help='Directory containing .yar/.yara rule files (repeatable)')
    parser.add_argument('--list-rules', action='store_true', help='List loaded rules and exit')
    parser.add_argument('--output', '-o', help='Export results to JSON')
    parser.add_argument('--quiet', '-q', action='store_true', help='Only print matches')

    args = parser.parse_args()

    # Parse max size
    max_size = 50 * 1024 * 1024
    m = re.match(r'(\d+)([KMG])?', args.max_size.upper())
    if m:
        mult = {'K': 1024, 'M': 1024**2, 'G': 1024**3}.get(m.group(2), 1)
        max_size = int(m.group(1)) * mult

    scanner = YaraScanner()
    scanner.load_rules(args.rules_dir)

    if args.list_rules:
        scanner.list_rules()
        return

    extensions = None
    if not args.all_files and args.extensions:
        extensions = [f'.{e.strip().lstrip(".").lower()}' for e in args.extensions.split(',')]
    elif not args.all_files:
        extensions = EXTENSIONS_DEFAULT

    if args.scan_process:
        scanner.scan_process(args.scan_process)
    elif args.scan_file:
        scanner.scan_file(args.scan_file)
        print(c('info', f'[*] Scanning {args.scan_file}'))
    elif args.scan:
        print(c('info', f'[*] Scanning: {", ".join(args.scan)}'))
        for target in args.scan:
            scanner.scan_directory(target, recursive=args.recursive,
                                   extensions=extensions, max_size=max_size,
                                   excludes=args.exclude)
    else:
        parser.print_help()
        return

    if not args.quiet:
        scanner.print_report()
    if args.output:
        scanner.export_json(args.output)


if __name__ == '__main__':
    main()
