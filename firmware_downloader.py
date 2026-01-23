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
from sys import argv, exit

from requests import request
from requests.exceptions import HTTPError

try:
    from anynet import tls
except ImportError:
    print("Module 'anynet' not found. Install it with: pip install anynet")
    exit(1)

warnings.filterwarnings("ignore")

ENV     = "lp1"
ARG_VERSION = argv[1] if len(argv) > 1 else ""
DEFAULT_CHANGELOG = "General system stability improvements to enhance the user's experience."

def readdata(f, addr, size):
    f.seek(addr); return f.read(size)

def utf8(s):
    return s.decode("utf-8")

def readint(f, addr=None):
    if addr is not None: f.seek(addr)
    return unpack("<I", f.read(4))[0]

def readshort(f, addr=None):
    if addr is not None: f.seek(addr)
    return unpack("<H", f.read(2))[0]

def hexify(s):
    return hexlify(s).decode("utf-8")

def ihexify(n, b):
    return hex(n)[2:].zfill(b * 2)

def dlfile(url, out):
    print(f"Downloading {basename(out)}...")
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

def dlfiles(dltable):
    if not dltable: return
    with open("dl.tmp", "w") as f:
        for url, dirc, fname, fhash in dltable:
            f.write(f"{url}\n\tout={fname}\n\tdir={dirc}\n\tchecksum=sha-256={fhash}\n")
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
    remove("dl.tmp")

def nin_request(method, url, headers=None):
    if headers is None: headers = {}
    headers.update({"User-Agent": user_agent})
    resp = request(
        method, url,
        cert=("keys/switch_client.crt", "keys/switch_client.key"),
        headers=headers, verify=False
    )
    if resp.status_code == 404:
        # 提供更详细的错误信息
        print(f"CDN Error: Resource Not Found (404) at {url}")
    resp.raise_for_status()
    return resp

def parse_cnmt(nca):
    ncaf = basename(nca)
    hactool_bin = "./hactool" 
    cnmt_temp_dir = f"cnmt_tmp_{ncaf}"
    run([hactool_bin, "-k", "prod.keys", nca, "--section0dir", cnmt_temp_dir], stdout=PIPE, stderr=PIPE, check=True)
    cnmt_file = glob(f"{cnmt_temp_dir}/*.cnmt")[0]
    entries = []
    with open(cnmt_file, "rb") as c:
        offset = readshort(c, 0xe)
        c_type = readdata(c, 0xc, 1)
        if c_type[0] == 0x3: # Meta
            n_entries = readshort(c, 0x12)
            base = 0x20 + offset
            for i in range(n_entries):
                c.seek(base + i*0x10)
                title_id = unpack("<Q", c.read(8))[0]
                version  = unpack("<I", c.read(4))[0]
                entries.append((ihexify(title_id, 8), version))
        else: # Application/Other
            n_entries = readshort(c, 0x10)
            base = 0x20 + offset
            for i in range(n_entries):
                c.seek(base + i*0x38)
                h = c.read(32); nid = hexify(c.read(16))
                entries.append((nid, hexify(h)))
    rmtree(cnmt_temp_dir)
    return entries

seen_titles = set()
queued_ncas = set()

def dltitle(title_id, version, is_su=False):
    global update_files, update_dls, sv_nca_fat, sv_nca_exfat, ver_string_simple
    key = (title_id, version, is_su)
    if key in seen_titles: return
    seen_titles.add(key)
    p = "s" if is_su else "a"
    
    url = f"https://atumn.hac.{ENV}.d4c.nintendo.net/t/{p}/{title_id}/{version}?device_id={device_id}"
    head_resp = nin_request("HEAD", url)
    cnmt_id = head_resp.headers["X-Nintendo-Content-ID"]
    
    ver_dir = f"Firmware {ver_string_simple}"
    makedirs(ver_dir, exist_ok=True)
    cnmt_nca = f"{ver_dir}/{cnmt_id}.cnmt.nca"
    update_files.append(cnmt_nca)
    dlfile(f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/{p}/{cnmt_id}?device_id={device_id}", cnmt_nca)
    
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
    try:
        rss_resp = request("GET", "https://yls8.mtheall.com/ninupdates/feed.php", timeout=10, verify=False)
        content = rss_resp.text
        target_title = f"Switch {version_str}"
        item_start = content.find(target_title)
        if item_start == -1: return DEFAULT_CHANGELOG
        link_start = content.find("<link>", item_start)
        link_end = content.find("</link>", link_start)
        report_url = html.unescape(content[link_start+6 : link_end].strip())
        report_resp = request("GET", report_url, timeout=10, verify=False)
        match = re.search(r'Changelog text</td>\s*<td.*?>(.*?)</td>', report_resp.text, re.I | re.S)
        if match: return re.sub(r'<[^>]+>', '', match.group(1).strip())
    except: pass
    return DEFAULT_CHANGELOG

if __name__ == "__main__":
    if not exists("certificat.pem") or not exists("prod.keys") or not exists("PRODINFO.bin"):
        print("ERROR: Missing required files (cert/keys/prodinfo)")
        exit(1)

    # 导出 Keys 用于请求
    pem_data = open("certificat.pem", "rb").read()
    cert = tls.TLSCertificate.parse(pem_data, tls.TYPE_PEM)
    priv = tls.TLSPrivateKey.parse(pem_data, tls.TYPE_PEM)
    makedirs("keys", exist_ok=True)
    cert.save("keys/switch_client.crt", tls.TYPE_PEM)
    priv.save("keys/switch_client.key", tls.TYPE_PEM)
    
    with open("PRODINFO.bin", "rb") as pf:
        device_id = utf8(readdata(pf, 0x2b56, 0x10))

    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"
    
    # 确定目标版本 (严格遵循传入参数)
    if not ARG_VERSION:
        print("ERROR: No version provided as argument!")
        exit(1)
    
    ver_string_simple = ARG_VERSION
    p = list(map(int, ver_string_simple.split(".")))
    while len(p) < 4: p.append(0)
    ver_raw = p[0]*0x4000000 + p[1]*0x100000 + p[2]*0x10000 + p[3]

    print(f"Processing Target Firmware: {ver_string_simple} (Raw ID: {ver_raw})")

    update_files = []; update_dls = []; sv_nca_fat = ""; sv_nca_exfat = ""
    seen_titles.clear(); queued_ncas.clear()

    # 执行下载逻辑
    dltitle("0100000000000816", ver_raw, is_su=True)
    if not sv_nca_exfat:
        try:
            dltitle("010000000000081B", ver_raw, is_su=False)
        except: 
            print("Notice: exFAT support title 081B not found/needed for this version.")

    if not update_files:
        print("ERROR: No files could be located for this version.")
        exit(1)

    dlfiles(update_dls)

    # 统计数据并生成结果文件
    total_size = 0
    all_data = b''
    for fpath in sorted(update_files):
        if exists(fpath):
            with open(fpath, 'rb') as f:
                d = f.read()
                all_data += d
                total_size += len(d)
    
    with open('firmware_info.txt', 'w') as f:
        f.write(f"VERSION={ver_string_simple}\n")
        f.write(f"FILES={len(update_files)}\n")
        f.write(f"SIZE_BYTES={total_size}\n")
        f.write(f"HASH={hashlib.sha256(all_data).hexdigest()}\n")
        f.write(f"CHANGELOG=\"{get_changelog_robust(ver_string_simple)}\"\n")
        f.write(f"SYSTEM_VERSION_FAT={sv_nca_fat}\n")
        f.write(f"SYSTEM_VERSION_EXFAT={sv_nca_exfat}\n")

    print(f"Success. Firmware {ver_string_simple} fully processed.")
