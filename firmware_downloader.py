#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import hashlib
import warnings
import json
from struct import unpack
from binascii import hexlify
from glob import glob
from shutil import rmtree
from subprocess import run, PIPE
from os import makedirs, remove
from os.path import basename, exists, join
from configparser import ConfigParser
from sys import argv, exit
from zipfile import ZipFile, ZIP_DEFLATED 

from requests import request
from requests.exceptions import HTTPError

try:
    from anynet import tls
except ImportError:
    print("Module 'anynet' not found. Install it with: pip install anynet")
    exit(1)

warnings.filterwarnings("ignore")

ENV     = "lp1"
# 如果命令行没有传参数，则 VERSION 为空，触发自动探测模式
VERSION = argv[1] if len(argv) > 1 and argv[1].strip() != "" else None

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
    # 优先尝试 Aria2，失败回退到 Requests
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
    except Exception:
        resp = request(
            "GET", url,
            cert=("keys/switch_client.crt", "keys/switch_client.key"),
            headers={"User-Agent": user_agent},
            stream=True, verify=False, timeout=60
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
    except Exception:
        print("Aria2 batch failed, falling back to sequential download...")
        for url, dirc, fname, fhash in dltable:
            makedirs(dirc, exist_ok=True)
            out = join(dirc, fname)
            dlfile(url, out)
    finally:
        if exists("dl.tmp"):
            remove("dl.tmp")

def nin_request(method, url, headers=None):
    if headers is None:
        headers = {}
    headers.update({"User-Agent": user_agent})
    resp = request(
        method, url,
        cert=("keys/switch_client.crt", "keys/switch_client.key"),
        headers=headers, verify=False, timeout=30
    )
    resp.raise_for_status()
    return resp

def parse_cnmt(nca):
    ncaf = basename(nca)
    # 兼容 Workflow 路径
    hactool_bin = "./hactool" if not os.name == "nt" else "hactool.exe" 
    
    if not exists(hactool_bin) and not os.name == "nt":
        print("::error::hactool binary not found!")
        exit(1)

    cnmt_temp_dir = f"cnmt_tmp_{ncaf}"
    
    run(
        [hactool_bin, "-k", "prod.keys", nca, "--section0dir", cnmt_temp_dir],
        stdout=PIPE, stderr=PIPE, check=True
    )
    
    cnmt_files = glob(f"{cnmt_temp_dir}/*.cnmt")
    if not cnmt_files:
        print(f"::error::No CNMT found in {nca}")
        exit(1)

    cnmt_file = cnmt_files[0]
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
    if key in seen_titles:
        return
    seen_titles.add(key)

    p = "s" if is_su else "a"
    try:
        cnmt_id = nin_request(
            "HEAD",
            f"https://atumn.hac.{ENV}.d4c.nintendo.net/t/{p}/{title_id}/{version}?device_id={device_id}"
        ).headers["X-Nintendo-Content-ID"]
    except HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            if title_id == "010000000000081B":
                # exFAT 404 是允许的
                return
            else:
                raise ValueError(f"Title {title_id} v{version} not found")
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
        for t_id, ver in parse_cnmt(cnmt_nca):
            dltitle(t_id, ver)
    else:
        for nca_id, nca_hash in parse_cnmt(cnmt_nca):
            if title_id == "0100000000000809":
                sv_nca_fat = f"{nca_id}.nca"
            elif title_id == "010000000000081B":
                sv_nca_exfat = f"{nca_id}.nca"

            if nca_id not in queued_ncas:
                queued_ncas.add(nca_id)
                update_files.append(f"{ver_dir}/{nca_id}.nca")
                update_dls.append((
                    f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/c/{nca_id}?device_id={device_id}",
                    ver_dir,
                    f"{nca_id}.nca",
                    nca_hash
                ))

def zipdir(src_dir, out_zip):
    print(f"Creating archive {out_zip}...")
    with ZipFile(out_zip, "w", compression=ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(src_dir):
            for name in files:
                full = os.path.join(root, name)
                rel  = os.path.relpath(full, start=src_dir) 
                zf.write(full, arcname=rel)

if __name__ == "__main__":
    if not exists("certificat.pem"):
        print("::error::certificat.pem not found")
        exit(1)
    pem_data = open("certificat.pem", "rb").read()
    cert = tls.TLSCertificate.parse(pem_data, tls.TYPE_PEM)
    priv = tls.TLSPrivateKey.parse(pem_data, tls.TYPE_PEM)
    makedirs("keys", exist_ok=True)
    cert.save("keys/switch_client.crt", tls.TYPE_PEM)
    priv.save("keys/switch_client.key", tls.TYPE_PEM)

    if not exists("prod.keys"):
        print("::error::prod.keys not found")
        exit(1)
    prod_keys = ConfigParser(strict=False)
    with open("prod.keys") as f: prod_keys.read_string("[keys]" + f.read())

    if not exists("PRODINFO.bin"):
        print("::error::PRODINFO.bin not found")
        exit(1)
    with open("PRODINFO.bin", "rb") as pf:
        if pf.read(4) != b"CAL0":
            print("::error::Invalid PRODINFO.bin")
            exit(1)
        device_id = utf8(readdata(pf, 0x2b56, 0x10))

    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"

    ver_raw = 0
    
    # === 彻底修复：版本决策逻辑 ===
    if VERSION is None:
        print("INFO: Auto-discovery mode (fetching Meta from Nintendo)...")
        try:
            # 直接问任天堂服务器最新版是多少
            su_meta = nin_request("GET", f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}").json()
            ver_raw = su_meta["system_update_metas"][0]["title_version"]
            
            # 反向计算显示名称
            v_maj = ver_raw // 0x4000000
            v_min = (ver_raw - v_maj*0x4000000) // 0x100000
            v_s1  = (ver_raw - v_maj*0x4000000 - v_min*0x100000) // 0x10000
            ver_string_simple = f"{v_maj}.{v_min}.{v_s1}"
            print(f"INFO: Nintendo Server reports latest version: {ver_string_simple} (Raw: {ver_raw})")
        except Exception as e:
            print(f"::error::Could not fetch Meta from Nintendo: {e}")
            exit(1)
    else:
        # 如果手动强行指定了版本（不推荐），则尝试计算
        print(f"INFO: Manual version requested: {VERSION}")
        ver_string_simple = VERSION
        parts = list(map(int, VERSION.split(".")))
        if len(parts) == 3: parts.append(0) 
        ver_raw = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]

    ver_dir = f"Firmware {ver_string_simple}"
    print(f"Downloading firmware. Target: {ver_dir}")

    update_files = []
    update_dls   = []
    sv_nca_fat   = ""
    sv_nca_exfat = ""

    seen_titles.clear()
    queued_ncas.clear()

    # 下载主系统固件
    try:
        dltitle("0100000000000816", ver_raw, is_su=True)
    except ValueError:
        print(f"::error::Primary Title 0100000000000816 v{ver_raw} not found on CDN!")
        print("::error::The keys provided might be for a different region, or the server is not ready.")
        exit(1)

    dlfiles(update_dls)

    # 下载 exFAT
    if not sv_nca_exfat:
        print("INFO: Downloading optional exFAT driver...")
        try:
            dltitle("010000000000081B", ver_raw, is_su=False)
            dlfiles(update_dls)
        except ValueError:
            print("INFO: exFAT driver not found (skipping).")

    # 验证
    failed = False
    for fpath in update_files:
        if not exists(fpath):
            print(f"::error::Download missing: {fpath}")
            failed = True
    if failed: exit(1)

    # 打包
    out_zip = f"{ver_dir}.zip" 
    if exists(out_zip): remove(out_zip)
    zipdir(ver_dir, out_zip)

    print("\nDOWNLOAD COMPLETE!")
    print(f"Archive created: {out_zip}")
    # 输出给 Workflow 捕获
    print(f"Folder: {ver_dir}")
