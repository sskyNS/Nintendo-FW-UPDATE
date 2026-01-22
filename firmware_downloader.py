#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
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
from os.path import basename, exists, join, dirname
from configparser import ConfigParser

from requests import request
from requests.exceptions import HTTPError

try:
    from anynet import tls
except ImportError:
    print("Module 'anynet' not found. Install it with: pip install anynet")
    sys.exit(1)

warnings.filterwarnings("ignore")

ENV     = "lp1"
VERSION = sys.argv[1] if len(sys.argv) > 1 else ""
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
        print(f"Downloading {basename(out)}...")
        run([
            "aria2c", "--no-conf", "--console-log-level=warn",
            "--file-allocation=none", "--summary-interval=0",
            "--download-result=hide",
            "--certificate=keys/switch_client.crt",
            "--private-key=keys/switch_client.key",
            f"--header=User-Agent: {user_agent}",
            "--check-certificate=false",
            f"--out={out}", "-c", url
        ], check=True)
        return True
    except FileNotFoundError:
        print(f"aria2c not found, using requests for {basename(out)}")
        try:
            resp = request(
                "GET", url,
                cert=("keys/switch_client.crt", "keys/switch_client.key"),
                headers={"User-Agent": user_agent},
                stream=True, verify=False, timeout=30
            )
            resp.raise_for_status()
            with open(out, "wb") as f:
                for chunk in resp.iter_content(1024*1024):
                    f.write(chunk)
            return True
        except Exception as e:
            print(f"Download failed: {e}")
            return False
    except Exception as e:
        print(f"Download failed: {e}")
        return False

def dlfiles(dltable):
    if not dltable:
        print("No files to download")
        return
    
    print(f"Batch downloading {len(dltable)} files...")
    
    # 创建下载目录
    for _, dirc, _, _ in dltable:
        makedirs(dirc, exist_ok=True)
    
    # 创建aria2输入文件
    with open("dl.tmp", "w") as f:
        for url, dirc, fname, fhash in dltable:
            f.write(f"{url}\n\tout={fname}\n\tdir={dirc}\n\tchecksum=sha-256={fhash}\n")
    
    try:
        run([
            "aria2c", "--no-conf", "--console-log-level=warn",
            "--file-allocation=none", "--summary-interval=0",
            "--download-result=hide",
            "--certificate=keys/switch_client.crt",
            "--private-key=keys/switch_client.key",
            f"--header=User-Agent: {user_agent}",
            "--check-certificate=false",
            "-x", "8", "-s", "8", "-i", "dl.tmp", "-j", "5"
        ], check=True)
        success = True
    except Exception as e:
        print(f"Batch download failed, trying individual downloads: {e}")
        success = True
        for url, dirc, fname, fhash in dltable:
            out = join(dirc, fname)
            if not dlfile(url, out):
                success = False
                print(f"Failed to download {fname}")
    
    # 清理临时文件
    try:
        remove("dl.tmp")
    except:
        pass
    
    return success

def nin_request(method, url, headers=None):
    if headers is None:
        headers = {}
    headers.update({"User-Agent": user_agent})
    
    try:
        resp = request(
            method, url,
            cert=("keys/switch_client.crt", "keys/switch_client.key"),
            headers=headers, verify=False, timeout=30
        )
        resp.raise_for_status()
        return resp
    except Exception as e:
        print(f"Request failed: {e}")
        raise

def parse_cnmt(nca):
    ncaf = basename(nca)
    hactool_bin = "hactool.exe" if os.name == "nt" else "./hactool"
    
    if not exists(hactool_bin):
        hactool_bin = "hactool"
    
    cnmt_temp_dir = f"cnmt_tmp_{ncaf}"
    makedirs(cnmt_temp_dir, exist_ok=True)
    
    try:
        result = run(
            [hactool_bin, "-k", "prod.keys", nca, "--section0dir", cnmt_temp_dir],
            stdout=PIPE, stderr=PIPE, text=True
        )
        
        if result.returncode != 0:
            print(f"hactool failed: {result.stderr}")
            rmtree(cnmt_temp_dir, ignore_errors=True)
            return []
        
        cnmt_files = glob(f"{cnmt_temp_dir}/*.cnmt")
        if not cnmt_files:
            print("No CNMT file found")
            rmtree(cnmt_temp_dir, ignore_errors=True)
            return []
        
        cnmt_file = cnmt_files[0]
        entries = []
        
        with open(cnmt_file, "rb") as c:
            c_type = readdata(c, 0xc, 1)
            if c_type[0] == 0x3:  # SystemUpdate
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
        
        rmtree(cnmt_temp_dir, ignore_errors=True)
        return entries
        
    except Exception as e:
        print(f"Error parsing CNMT: {e}")
        rmtree(cnmt_temp_dir, ignore_errors=True)
        return []

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
        # 获取内容ID
        resp = nin_request(
            "HEAD",
            f"https://atumn.hac.{ENV}.d4c.nintendo.net/t/{p}/{title_id}/{version}?device_id={device_id}"
        )
        
        if "X-Nintendo-Content-ID" not in resp.headers:
            print(f"No content ID for title {title_id}")
            return
            
        cnmt_id = resp.headers["X-Nintendo-Content-ID"]
        
    except HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print(f"Title {title_id} not found (404)")
            if title_id == "010000000000081B":
                sv_nca_exfat = ""
            return
        print(f"Error accessing title {title_id}: {e}")
        return
    except Exception as e:
        print(f"Error accessing title {title_id}: {e}")
        return
    
    ver_dir = f"Firmware {ver_string_simple}"
    makedirs(ver_dir, exist_ok=True)
    
    cnmt_nca = f"{ver_dir}/{cnmt_id}.cnmt.nca"
    update_files.append(cnmt_nca)
    
    print(f"Downloading CNMT for title {title_id}...")
    if not dlfile(
        f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/{p}/{cnmt_id}?device_id={device_id}",
        cnmt_nca
    ):
        print(f"Failed to download CNMT for {title_id}")
        return
    
    if is_su:
        # System Update - 递归下载子内容
        for t_id, ver in parse_cnmt(cnmt_nca):
            dltitle(t_id, ver)
    else:
        # 普通内容 - 下载实际文件
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
                    ver_dir, f"{nca_id}.nca", nca_hash
                ))

def get_changelog_robust(version_str):
    print(f"Attempting to fetch changelog for version {version_str}...")
    
    try:
        rss_url = "https://yls8.mtheall.com/ninupdates/feed.php"
        rss_resp = request("GET", rss_url, headers={"User-Agent": user_agent}, verify=False, timeout=10)
        
        if rss_resp.status_code != 200:
            print(f"RSS feed returned status {rss_resp.status_code}")
            return DEFAULT_CHANGELOG
        
        content = rss_resp.text
        target_title = f"Switch {version_str}"
        item_start = content.find(target_title)
        
        if item_start == -1:
            print(f"Version {version_str} not found in RSS feed")
            return DEFAULT_CHANGELOG
        
        # 提取报告链接
        link_start = content.find("<link>", item_start)
        link_end = content.find("</link>", link_start)
        
        if link_start == -1 or link_end == -1:
            print("No link found in RSS item")
            return DEFAULT_CHANGELOG
        
        report_url = content[link_start+6 : link_end].strip()
        report_url = html.unescape(report_url)
        print(f"Found report URL: {report_url}")
        
        # 获取报告页面
        report_resp = request("GET", report_url, headers={"User-Agent": user_agent}, verify=False, timeout=10)
        if report_resp.status_code != 200:
            print(f"Report page returned status {report_resp.status_code}")
            return DEFAULT_CHANGELOG
        
        # 提取变更日志
        report_text = report_resp.text
        changelog_patterns = [
            r'Changelog text</td>\s*<td[^>]*>(.*?)</td>',
            r'Change.*?log.*?</td>\s*<td[^>]*>(.*?)</td>',
            r'Update.*?note.*?</td>\s*<td[^>]*>(.*?)</td>',
        ]
        
        changelog = ""
        for pattern in changelog_patterns:
            match = re.search(pattern, report_text, re.IGNORECASE | re.DOTALL)
            if match:
                changelog = match.group(1).strip()
                break
        
        if changelog:
            # 清理HTML标签
            changelog = re.sub(r'<[^>]+>', '', changelog)
            changelog = re.sub(r'\s+', ' ', changelog).strip()
            
            if len(changelog) > 10:  # 确保有实际内容
                print(f"Found changelog: {changelog[:100]}...")
                return changelog
        
        print("No changelog found in report")
        return DEFAULT_CHANGELOG
        
    except Exception as e:
        print(f"Changelog fetch error: {e}")
        return DEFAULT_CHANGELOG

def main():
    global device_id, user_agent, ver_string_simple, ver_string_raw, ver_raw
    global update_files, update_dls, sv_nca_fat, sv_nca_exfat
    
    print("=== Firmware Downloader ===")
    
    # 检查必需文件
    if not exists("certificat.pem"):
        print("Error: certificat.pem not found!")
        sys.exit(1)
    
    if not exists("prod.keys"):
        print("Error: prod.keys not found!")
        sys.exit(1)
    
    if not exists("PRODINFO.bin"):
        print("Error: PRODINFO.bin not found!")
        sys.exit(1)
    
    # 准备TLS证书
    print("Preparing TLS certificate...")
    try:
        pem_data = open("certificat.pem", "rb").read()
        cert = tls.TLSCertificate.parse(pem_data, tls.TYPE_PEM)
        priv = tls.TLSPrivateKey.parse(pem_data, tls.TYPE_PEM)
        makedirs("keys", exist_ok=True)
        cert.save("keys/switch_client.crt", tls.TYPE_PEM)
        priv.save("keys/switch_client.key", tls.TYPE_PEM)
    except Exception as e:
        print(f"Error preparing certificate: {e}")
        sys.exit(1)
    
    # 读取生产密钥
    try:
        prod_keys = ConfigParser(strict=False)
        with open("prod.keys") as f:
            prod_keys.read_string("[keys]" + f.read())
    except Exception as e:
        print(f"Error reading prod.keys: {e}")
        sys.exit(1)
    
    # 读取设备ID
    try:
        with open("PRODINFO.bin", "rb") as pf:
            if pf.read(4) != b"CAL0":
                print("Error: Invalid PRODINFO.bin format!")
                sys.exit(1)
            device_id = utf8(readdata(pf, 0x2b56, 0x10))
            print(f"Device ID: {device_id}")
    except Exception as e:
        print(f"Error reading PRODINFO.bin: {e}")
        sys.exit(1)
    
    # 设置User-Agent
    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"
    
    # 确定要下载的版本
    if VERSION == "":
        print("INFO: Searching for latest version...")
        try:
            su_meta = nin_request("GET", f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}").json()
            ver_raw = su_meta["system_update_metas"][0]["title_version"]
            ver_major = ver_raw // 0x4000000
            ver_minor = (ver_raw - ver_major*0x4000000) // 0x100000
            ver_sub1  = (ver_raw - ver_major*0x4000000 - ver_minor*0x100000) // 0x10000
            ver_sub2  = ver_raw - ver_major*0x4000000 - ver_minor*0x100000 - ver_sub1*0x10000
            ver_string_raw = f"{ver_major}.{ver_minor}.{ver_sub1}.{str(ver_sub2).zfill(4)}"
            ver_string_simple = f"{ver_major}.{ver_minor}.{ver_sub1}"
        except Exception as e:
            print(f"Error getting latest version: {e}")
            sys.exit(1)
    else:
        ver_string_simple = VERSION
        parts = list(map(int, VERSION.split(".")))
        if len(parts) == 3:
            parts.append(0)
        elif len(parts) != 4:
            print(f"Error: Invalid version format: {VERSION}")
            sys.exit(1)
            
        ver_raw = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]
        ver_string_raw = f"{parts[0]}.{parts[1]}.{parts[2]}.{str(parts[3]).zfill(4)}"
    
    print(f"Downloading firmware {ver_string_simple} (raw: {ver_string_raw})...")
    
    # 创建输出目录
    ver_dir = f"Firmware {ver_string_simple}"
    makedirs(ver_dir, exist_ok=True)
    print(f"Output directory: {ver_dir}")
    
    # 初始化下载列表
    update_files = []
    update_dls   = []
    sv_nca_fat   = ""
    sv_nca_exfat = ""
    seen_titles.clear()
    queued_ncas.clear()
    
    # 下载系统更新元数据
    print("Downloading system update metadata...")
    dltitle("0100000000000816", ver_raw, is_su=True)
    
    # 检查是否下载了exFAT支持
    if not sv_nca_exfat:
        print("INFO: exFAT not found via meta, attempting separate title...")
        dltitle("010000000000081B", ver_raw, is_su=False)
    
    # 批量下载文件
    print(f"Starting batch download for {len(update_dls)} files...")
    if not dlfiles(update_dls):
        print("Error: Batch download failed!")
        sys.exit(1)
    
    # 验证所有文件都已下载
    failed = False
    for fpath in update_files:
        if not exists(fpath):
            print(f"Error: Missing file {fpath}")
            failed = True
    
    if failed:
        print("Error: Some files failed to download!")
        sys.exit(1)
    
    # 获取变更日志
    changelog_text = get_changelog_robust(ver_string_simple)
    
    # 计算验证数据
    print("Calculating verification data...")
    all_data = b''
    total_size = 0
    
    for fpath in sorted(update_files):
        try:
            with open(fpath, 'rb') as f:
                file_data = f.read()
                all_data += file_data
                total_size += len(file_data)
        except Exception as e:
            print(f"Error reading {fpath}: {e}")
            sys.exit(1)
    
    total_hash = hashlib.sha256(all_data).hexdigest()
    
    # 写入信息文件
    print(f"Writing firmware_info.txt...")
    with open('firmware_info.txt', 'w') as f:
        f.write(f"VERSION={ver_string_simple}\n")
        f.write(f"FILES={len(update_files)}\n")
        f.write(f"SIZE_BYTES={total_size}\n")
        f.write(f"HASH={total_hash}\n")
        f.write(f"CHANGELOG={changelog_text}\n")
        f.write(f"SYSTEM_VERSION_FAT={sv_nca_fat}\n")
        f.write(f"SYSTEM_VERSION_EXFAT={sv_nca_exfat}\n")
    
    print(f"Done. Downloaded {len(update_files)} files, total size: {total_size:,} bytes")
    print(f"Firmware folder: {ver_dir}")
    print(f"Info saved to firmware_info.txt")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
