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

# --- Helper Functions ---
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
        c_type = readdata(c, 0xc, 1)
        if c_type[0] == 0x3:
            n_entries = readshort(c, 0x12)
            offset = readshort(c, 0xe)
            base = 0x20 + offset
            for i in range(n_entries):
                c.seek(base + i*0x10)
                title_id = unpack("<Q", c.read(8))[0]
                version  = unpack("<I", c.read(4))[0]
                entries.append((ihexify(title_id, 8), version))
        else:
            n_entries = readshort(c, 0x10)
            offset = readshort(c, 0xe)
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
        # 增加超时和更真实的 UA
        rss_resp = request("GET", "https://yls8.mtheall.com/ninupdates/feed.php", timeout=15, verify=False)
        content = rss_resp.text
        
        # 使用正则严格匹配 <title>Switch 版本号</title>
        # 排除 "Switch 2"
        # 这里的正则含义：寻找 <title> 标签，开头必须是 Switch [版本号]，后面紧跟 </title>
        # 这样就不会误匹配到 "Switch 2 21.2.0"
        title_pattern = rf"<title>Switch {re.escape(version_str)}</title>"
        
        # 先找到 item 的起始位置
        match_title = re.search(title_pattern, content)
        if not match_title:
            return DEFAULT_CHANGELOG
            
        # 从标题位置开始往后找第一个 <link>
        item_content = content[match_title.start():]
        link_match = re.search(r"<link>(.*?)</link>", item_content, re.S)
        if not link_match:
            return DEFAULT_CHANGELOG
            
        report_url = html.unescape(link_match.group(1).strip())
        
        # 抓取具体的报表页面
        report_resp = request("GET", report_url, timeout=15, verify=False)
        # 提取 Changelog text 栏目
        match_text = re.search(r'Changelog text</td>\s*<td.*?>(.*?)</td>', report_resp.text, re.I | re.S)
        if match_text:
            # 过滤 HTML 标签并处理转义字符
            clean_text = re.sub(r'<[^>]+>', '', match_text.group(1).strip())
            return html.unescape(clean_text)
            
    except Exception as e:
        print(f"Warning: Failed to fetch changelog: {e}")
    return DEFAULT_CHANGELOG
if __name__ == "__main__":
    if not exists("certificat.pem") or not exists("prod.keys") or not exists("PRODINFO.bin"):
        print("ERROR: Missing required files")
        exit(1)
        
    pem_data = open("certificat.pem", "rb").read()
    cert = tls.TLSCertificate.parse(pem_data, tls.TYPE_PEM)
    priv = tls.TLSPrivateKey.parse(pem_data, tls.TYPE_PEM)
    makedirs("keys", exist_ok=True)
    cert.save("keys/switch_client.crt", tls.TYPE_PEM)
    priv.save("keys/switch_client.key", tls.TYPE_PEM)
    
    with open("PRODINFO.bin", "rb") as pf:
        device_id = utf8(readdata(pf, 0x2b56, 0x10))

    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"
    
    meta_ver_string = ""
    meta_ver_raw = 0
    try:
        su_meta = nin_request("GET", f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}").json()
        meta_ver_raw = su_meta["system_update_metas"][0]["title_version"]
        v = meta_ver_raw
        meta_ver_string = f"{v//0x4000000}.{(v%0x4000000)//0x100000}.{(v%0x100000)//0x10000}"
    except:
        pass

    target_ver_string = ARG_VERSION if ARG_VERSION else meta_ver_string
    
    def get_raw_id(v_str):
        p = list(map(int, v_str.split(".")))
        while len(p) < 4: p.append(0)
        return p[0]*0x4000000 + p[1]*0x100000 + p[2]*0x10000 + p[3]

    current_attempt_ver = target_ver_string
    current_attempt_raw = get_raw_id(current_attempt_ver)

    update_files = []; update_dls = []; sv_nca_fat = ""; sv_nca_exfat = ""

    try:
        print(f"Targeting Firmware: {current_attempt_ver} (ID: {current_attempt_raw})")
        dltitle("0100000000000816", current_attempt_raw, is_su=True)
    except HTTPError as e:
        if e.response.status_code == 404:
            print(f"FAILED: Version {current_attempt_ver} not found on CDN (404).")
            if meta_ver_string and current_attempt_ver != meta_ver_string:
                print(f"FALLBACK: Reverting to Meta Server version: {meta_ver_string}")
                current_attempt_ver = meta_ver_string
                current_attempt_raw = meta_ver_raw
                seen_titles.clear(); queued_ncas.clear()
                update_files = []; update_dls = []
                dltitle("0100000000000816", current_attempt_raw, is_su=True)
            else:
                print("CRITICAL: No fallback version available or fallback also failed.")
                exit(1)
        else:
            raise

    if not sv_nca_exfat:
        try:
            dltitle("010000000000081B", current_attempt_raw, is_su=False)
        except: pass

    ver_string_simple = current_attempt_ver
    dlfiles(update_dls)

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

    print(f"Successfully processed Firmware {ver_string_simple}")
