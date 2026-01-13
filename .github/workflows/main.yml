#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import hashlib
import warnings
import re
import html
from struct import unpack
from binascii import hexlify
from glob import glob
from shutil import rmtree
from subprocess import run, PIPE
from os import makedirs, remove
from os.path import basename, exists, join
from configparser import ConfigParser
from sys import argv

from requests import request
from requests.exceptions import HTTPError

try:
    from anynet import tls
except ImportError:
    print("Module 'anynet' not found. Install it with: pip install anynet")
    exit(1)

warnings.filterwarnings("ignore")

ENV     = "lp1"
VERSION = argv[1] if len(argv) > 1 else ""
DEFAULT_CHANGELOG = "General system stability improvements to enhance the user's experience."

def readdata(f, addr, size):
    f.seek(addr)
    return f.read(size)

def utf8(s):
    return s.decode("utf-8")

def sha256(s):
    return hashlib.sha256(s).digest()

def readint(f, addr=None):
    if addr is not None:
        f.seek(addr)
    return unpack("<I", f.read(4))[0]

def readshort(f, addr=None):
    if addr is not None:
        f.seek(addr)
    return unpack("<H", f.read(2))[0]

def hexify(s):
    return hexlify(s).decode("utf-8")

def ihexify(n, b):
    return hex(n)[2:].zfill(b * 2)

def dlfile(url, out):
    try:
        run([
            "aria2c", "--no-conf", "--console-log-level=error",
            "--file-allocation=none", "--summary-interval=0",
            "--download-result=hide",
            "--certificate=keys/switch_client.crt",
            "--private-key=keys/switch_client.key",
            f"--header=User-Agent: {user_agent}",
            "--check-certificate=false",
            f"--out={out}", "-c", url
        ], check=True)
    except FileNotFoundError:
        print(f"downloading {basename(out)} via requests")
        resp = request(
            "GET", url,
            cert=("keys/switch_client.crt", "keys/switch_client.key"),
            headers={"User-Agent": user_agent},
            stream=True, verify=False
        )
        resp.raise_for_status()
        with open(out, "wb") as f:
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)

def dlfiles(dltable):
    with open("dl.tmp", "w") as f:
        for url, dirc, fname, fhash in dltable:
            f.write(f"{url}\n\tout={fname}\n\tdir={dirc}\n\tchecksum=sha-256={fhash}\n")
    try:
        run([
            "aria2c", "--no-conf", "--console-log-level=error",
            "--file-allocation=none", "--summary-interval=0",
            "--download-result=hide",
            "--certificate=keys/switch_client.crt",
            "--private-key=keys/switch_client.key",
            f"--header=User-Agent: {user_agent}",
            "--check-certificate=false",
            "-x", "16", "-s", "16", "-i", "dl.tmp"
        ], check=True)
    except FileNotFoundError:
        for url, dirc, fname, fhash in dltable:
            makedirs(dirc, exist_ok=True)
            out = join(dirc, fname)
            dlfile(url, out)
    finally:
        try:
            remove("dl.tmp")
        except FileNotFoundError:
            pass

def nin_request(method, url, headers=None):
    if headers is None:
        headers = {}
    headers.update({"User-Agent": user_agent})
    resp = request(
        method, url,
        cert=("keys/switch_client.crt", "keys/switch_client.key"),
        headers=headers, verify=False
    )
    resp.raise_for_status()
    return resp

def parse_cnmt(nca):
    ncaf = basename(nca)
    hactool_bin = "hactool.exe" if os.name == "nt" else "./hactool" 
    cnmt_temp_dir = f"cnmt_tmp_{ncaf}"
    run(
        [hactool_bin, "-k", "prod.keys", nca, "--section0dir", cnmt_temp_dir],
        stdout=PIPE, stderr=PIPE
    )
    cnmt_file = glob(f"{cnmt_temp_dir}/*.cnmt")[0]
    entries = []
    with open(cnmt_file, "rb") as c:
        c_type = readdata(c, 0xc, 1)
        if c_type[0] == 0x3:
            n_entries = readshort(c, 0x12)
            offset    = readshort(c, 0xe)
            base = 0x20 + offset
            for i in range(n_entries):
                c.seek(base + i*0x10)
                title_id = unpack("<Q", c.read(8))[0]
                version  = unpack("<I", c.read(4))[0]
                entries.append((ihexify(title_id, 8), version))
        else:
            n_entries = readshort(c, 0x10)
            offset    = readshort(c, 0xe)
            base = 0x20 + offset
            for i in range(n_entries):
                c.seek(base + i*0x38)
                h      = c.read(32)
                nid    = hexify(c.read(16))
                entries.append((nid, hexify(h)))
    rmtree(cnmt_temp_dir)
    return entries

seen_titles = set()
queued_ncas = set()

def dltitle(title_id, version, is_su=False):
    global update_files, update_dls, sv_nca_fat, sv_nca_exfat, seen_titles, queued_ncas, ver_string_simple
    key = (title_id, version, is_su)
    if key in seen_titles: return
    seen_titles.add(key)
    p = "s" if is_su else "a"
    try:
        cnmt_id = nin_request(
            "HEAD",
            f"https://atumn.hac.{ENV}.d4c.nintendo.net/t/{p}/{title_id}/{version}?device_id={device_id}"
        ).headers["X-Nintendo-Content-ID"]
    except HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            if title_id == "010000000000081B": sv_nca_exfat = ""
            return
        raise
    ver_dir = f"Firmware {ver_string_simple}"
    makedirs(ver_dir, exist_ok=True)
    cnmt_nca = f"{ver_dir}/{cnmt_id}.cnmt.nca"
    update_files.append(cnmt_nca)
    dlfile(
        f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/{p}/{cnmt_id}?device_id={device_id}",
        cnmt_nca
    )
    if is_su:
        for t_id, ver in parse_cnmt(cnmt_nca): dltitle(t_id, ver)
    else:
        for nca_id, nca_hash in parse_cnmt(cnmt_nca):
            if title_id == "0100000000000809": sv_nca_fat = f"{nca_id}.nca"
            elif title_id == "010000000000081B": sv_nca_exfat = f"{nca_id}.nca"
            if nca_id not in queued_ncas:
                queued_ncas.add(nca_id)
                update_files.append(f"{ver_dir}/{nca_id}.nca")
                update_dls.append((
                    f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/c/{nca_id}?device_id={device_id}",
                    ver_dir, f"{nca_id}.nca", nca_hash
                ))

def get_changelog_robust(version_str):
    print("Attempting to fetch changelog...")
    try:
        rss_url = "https://yls8.mtheall.com/ninupdates/feed.php"
        rss_resp = request("GET", rss_url, headers={"User-Agent": user_agent}, verify=False, timeout=10)
        if rss_resp.status_code != 200: return DEFAULT_CHANGELOG

        content = rss_resp.text
        target_title = f"Switch {version_str}"
        item_start = content.find(target_title)
        
        if item_start == -1: return DEFAULT_CHANGELOG
            
        link_start = content.find("<link>", item_start)
        link_end = content.find("</link>", link_start)
        
        if link_start == -1 or link_end == -1: return DEFAULT_CHANGELOG
            
        report_url = content[link_start+6 : link_end].strip()
        report_url = html.unescape(report_url)
        print(f"Found report URL: {report_url}")

        report_resp = request("GET", report_url, headers={"User-Agent": user_agent}, verify=False, timeout=10)
        if report_resp.status_code == 200:
            match = re.search(r'Changelog text</td>\s*<td.*?>(.*?)</td>', report_resp.text, re.IGNORECASE | re.DOTALL)
            if match:
                text = match.group(1).strip()
                text = re.sub(r'<[^>]+>', '', text)
                text = re.sub(r'\s+', ' ', text)
                if len(text) > 5:
                    return text
    except Exception as e:
        print(f"Changelog fetch error: {e}")
    
    return DEFAULT_CHANGELOG

if __name__ == "__main__":
    if not exists("certificat.pem"): exit(1)
    pem_data = open("certificat.pem", "rb").read()
    cert = tls.TLSCertificate.parse(pem_data, tls.TYPE_PEM)
    priv = tls.TLSPrivateKey.parse(pem_data, tls.TYPE_PEM)
    makedirs("keys", exist_ok=True)
    cert.save("keys/switch_client.crt", tls.TYPE_PEM)
    priv.save("keys/switch_client.key", tls.TYPE_PEM)

    if not exists("prod.keys"): exit(1)
    prod_keys = ConfigParser(strict=False)
    with open("prod.keys") as f: prod_keys.read_string("[keys]" + f.read())

    if not exists("PRODINFO.bin"): exit(1)
    with open("PRODINFO.bin", "rb") as pf:
        if pf.read(4) != b"CAL0": exit(1)
        device_id = utf8(readdata(pf, 0x2b56, 0x10))

    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"

    if VERSION == "":
        print("INFO: Searching for latest version...")
        su_meta = nin_request("GET", f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}").json()
        ver_raw = su_meta["system_update_metas"][0]["title_version"]
        ver_major = ver_raw // 0x4000000
        ver_minor = (ver_raw - ver_major*0x4000000) // 0x100000
        ver_sub1  = (ver_raw - ver_major*0x4000000 - ver_minor*0x100000) // 0x10000
        ver_sub2  = ver_raw - ver_major*0x4000000 - ver_minor*0x100000 - ver_sub1*0x10000
        ver_string_raw = f"{ver_major}.{ver_minor}.{ver_sub1}.{str(ver_sub2).zfill(4)}"
        ver_string_simple = f"{ver_major}.{ver_minor}.{ver_sub1}"
    else:
        ver_string_simple = VERSION
        parts = list(map(int, VERSION.split(".")))
        if len(parts) == 3: parts.append(0) 
        ver_raw = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]
        ver_string_raw = f"{parts[0]}.{parts[1]}.{parts[2]}.{str(parts[3]).zfill(4)}"

    ver_dir = f"Firmware {ver_string_simple}"
    print(f"Downloading firmware {ver_string_simple}...")

    update_files = []
    update_dls   = []
    sv_nca_fat   = ""
    sv_nca_exfat = ""
    seen_titles.clear()
    queued_ncas.clear()

    dltitle("0100000000000816", ver_raw, is_su=True)
    
    if not sv_nca_exfat:
        print("INFO: exFAT not found via meta, attempting separate title...")
        dltitle("010000000000081B", ver_raw, is_su=False)

    print(f"Starting batch download for {len(update_dls)} files...")
    dlfiles(update_dls)

    failed = False
    for fpath in update_files:
        if not exists(fpath): failed = True
    if failed: exit(1)

    changelog_text = get_changelog_robust(ver_string_simple)

    print("Calculating verification data...")
    all_data = b''
    total_size = 0
    for fpath in sorted(update_files):
        with open(fpath, 'rb') as f:
            file_data = f.read()
            all_data += file_data
            total_size += len(file_data)
    
    total_hash = hashlib.sha256(all_data).hexdigest()

    with open('firmware_info.txt', 'w') as f:
        f.write(f"VERSION={ver_string_simple}\n")
        f.write(f"FILES={len(update_files)}\n")
        f.write(f"SIZE_BYTES={total_size}\n")
        f.write(f"HASH={total_hash}\n")
        f.write(f"CHANGELOG={changelog_text}\n")
        f.write(f"SYSTEM_VERSION_FAT={sv_nca_fat}\n")
        f.write(f"SYSTEM_VERSION_EXFAT={sv_nca_exfat}\n")

    print(f"Done. Info saved to firmware_info.txt")
