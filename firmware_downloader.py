#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import hashlib
import warnings
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
VERSION = argv[1] if len(argv) > 1 else ""

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
    except Exception:
        # print(f"Aria2 failed, using requests for {basename(out)}")
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
    except Exception:
        print("Aria2 batch failed, sequential download...")
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
        headers=headers, verify=False
    )
    resp.raise_for_status()
    return resp

def parse_cnmt(nca):
    ncaf = basename(nca)
    # 兼容 Workflow 中的 hactool 路径
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
            # 只有 exFAT 允许 404，主系统 404 需要抛出异常以便主循环重试
            if title_id == "010000000000081B":
                print(f"INFO: exFAT update not found (optional).")
                sv_nca_exfat = ""
                return
            else:
                # 这是一个关键修改：抛出异常让主程序知道这个 version 不对
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
    with open("prod.keys") as f:
        prod_keys.read_string("[keys]" + f.read())

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
    
    if VERSION == "":
        print("INFO: Fetching Meta for latest version...")
        try:
            su_meta = nin_request("GET", f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}").json()
            ver_raw = su_meta["system_update_metas"][0]["title_version"]
            # 简单的转换，不处理复杂字符串
            v_maj = ver_raw // 0x4000000
            v_min = (ver_raw - v_maj*0x4000000) // 0x100000
            v_s1  = (ver_raw - v_maj*0x4000000 - v_min*0x100000) // 0x10000
            ver_string_simple = f"{v_maj}.{v_min}.{v_s1}"
        except:
            print("::error::Could not fetch Meta.")
            exit(1)
    else:
        ver_string_simple = VERSION
        parts = list(map(int, VERSION.split(".")))
        if len(parts) == 3: parts.append(0) 
        ver_raw = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]

    ver_dir = f"Firmware {ver_string_simple}"
    print(f"Downloading firmware. Internal ID: {ver_raw}. Folder: {ver_dir}")

    update_files = []
    update_dls   = []
    sv_nca_fat   = ""
    sv_nca_exfat = ""

    seen_titles.clear()
    queued_ncas.clear()

    # === 核心修复：扫描版本号 (Revision Scanning) ===
    # 即使使用参考代码，如果不加这个循环，遇到 404 就真的没办法了。
    # 这里的修改是隐形的，保持了原有代码逻辑，只是多试几次。
    
    found_any = False
    for offset in range(0, 16):
        try_ver = ver_raw + offset
        try:
            # 清除 seen_titles 确保每次尝试都是新的
            seen_titles.clear()
            dltitle("0100000000000816", try_ver, is_su=True)
            print(f"INFO: Successfully matched version revision +{offset}")
            ver_raw = try_ver # 锁定正确的版本号
            found_any = True
            break
        except ValueError:
            # dltitle 抛出的异常，说明这个 offset 不对，继续尝试下一个
            continue
        except Exception as e:
            print(f"::error::Unexpected error: {e}")
            exit(1)

    if not found_any:
        print(f"::error::Failed to find Firmware {ver_string_simple} on CDN (tried 16 revisions). Wait for propagation.")
        exit(1)

    # 下载文件队列
    dlfiles(update_dls)

    # 处理 exFAT (使用找到的正确 ver_raw)
    if not sv_nca_exfat:
        print("INFO: Attempting to download exFAT driver...")
        try:
            dltitle("010000000000081B", ver_raw, is_su=False)
            dlfiles(update_dls) # 再次调用下载
        except ValueError:
            print("INFO: exFAT driver not found (skipping).")

    # 验证文件是否存在
    failed = False
    for fpath in update_files:
        if not exists(fpath):
            print(f"::error::Download failed, missing: {fpath}")
            failed = True
    if failed:
        exit(1)

    # 打包
    out_zip = f"{ver_dir}.zip" 
    if exists(out_zip): remove(out_zip)
    zipdir(ver_dir, out_zip)

    print("\nDOWNLOAD COMPLETE!")
    print(f"Archive created: {out_zip}")
    print(f"SystemVersion NCA FAT: {sv_nca_fat or 'Not Found'}")
    print(f"SystemVersion NCA exFAT: {sv_nca_exfat or 'Not Found'}")
