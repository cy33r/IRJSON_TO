import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import urllib.parse
import urllib.request
import ssl
import base64
import threading
import traceback
import sys

# --- Logic Functions ---

def generate_vless_vmess_url(outbound, remark_base, index):
    try:
        protocol = outbound.get("protocol")
        if not protocol: return None

        settings = outbound.get("settings", {})
        stream_settings = outbound.get("streamSettings", {})
        network = stream_settings.get("network", "tcp")
        security = stream_settings.get("security", "none")
        
        tag = outbound.get("tag", "")
        if tag and tag != "proxy":
             final_name = f"{remark_base}-{tag}"
        else:
             final_name = remark_base
             
        safe_remark = urllib.parse.quote(final_name)

        address = ""
        port = 0
        uuid_pass = ""

        # VLESS / TROJAN
        if protocol in ["vless", "trojan"]:
            if "vnext" in settings and settings["vnext"]:
                target = settings["vnext"][0]
                address = target.get("address", "")
                port = target.get("port", 0)
                if protocol == "vless" and target.get("users"):
                    uuid_pass = target["users"][0].get("id", "")
                elif protocol == "trojan":
                     pws = target.get("password", [])
                     if isinstance(pws, list) and pws: uuid_pass = pws[0]
                     elif isinstance(pws, str): uuid_pass = pws

            elif "servers" in settings and settings["servers"]:
                target = settings["servers"][0]
                address = target.get("address", "")
                port = target.get("port", 0)
                if protocol == "trojan":
                    uuid_pass = target.get("password", "")
            
            if not address or not uuid_pass:
                return None

            params = {"type": network, "security": security}
            
            if network == "ws":
                ws = stream_settings.get("wsSettings", {})
                if "path" in ws: params["path"] = ws["path"]
                headers = ws.get("headers", {})
                if "Host" in headers: params["host"] = headers["Host"]
                elif "host" in ws: params["host"] = ws["host"]
            
            elif network == "grpc":
                grpc = stream_settings.get("grpcSettings", {})
                if "serviceName" in grpc: params["serviceName"] = grpc["serviceName"]
                if "mode" in grpc: params["mode"] = grpc["mode"]

            if security in ["tls", "xtls", "reality"]:
                tls = stream_settings.get("tlsSettings") or stream_settings.get("xtlsSettings") or stream_settings.get("realitySettings") or {}
                if "serverName" in tls: params["sni"] = tls["serverName"]
                if "alpn" in tls and tls["alpn"]: params["alpn"] = ",".join(tls["alpn"])
                
                if security == "reality":
                    if "publicKey" in tls: params["pbk"] = tls["publicKey"]
                    if "shortIds" in tls: params["sid"] = tls["shortIds"][0]
                    if "fingerprint" in tls: params["fp"] = tls["fingerprint"]
                    if "spiderX" in tls: params["spx"] = tls["spiderX"]

            query = urllib.parse.urlencode(params)
            return f"{protocol}://{uuid_pass}@{address}:{port}?{query}#{safe_remark}"

        # --- VMESS ---
        elif protocol == "vmess":
            if "vnext" in settings and settings["vnext"]:
                target = settings["vnext"][0]
                address = target.get("address", "")
                port = target.get("port", 0)
                users = target.get("users", [{}])
                uuid = users[0].get("id", "")
                alterId = users[0].get("alterId", 0)

                vmess_dict = {
                    "v": "2", "ps": urllib.parse.unquote(safe_remark), 
                    "add": address, "port": port, "id": uuid, "aid": alterId,
                    "net": network, "type": "none", "host": "", "path": "", 
                    "tls": security if security != "none" else ""
                }

                if network == "ws":
                    ws = stream_settings.get("wsSettings", {})
                    vmess_dict["path"] = ws.get("path", "")
                    headers = ws.get("headers", {})
                    vmess_dict["host"] = headers.get("Host", ws.get("host", ""))
                elif network == "grpc":
                    grpc = stream_settings.get("grpcSettings", {})
                    vmess_dict["path"] = grpc.get("serviceName", "")
                    vmess_dict["type"] = grpc.get("mode", "gun")

                if security in ["tls", "reality"]:
                    tls = stream_settings.get("tlsSettings") or stream_settings.get("realitySettings") or {}
                    vmess_dict["sni"] = tls.get("serverName", "")

                b64 = base64.b64encode(json.dumps(vmess_dict).encode()).decode()
                return f"vmess://{b64}"

    except Exception:
        return None
    return None

def process_single_item(item, index, default_remark="VIP3R"):
    extracted_links = []
    local_remark = item.get("remarks", default_remark)
    
    if "outbounds" in item and isinstance(item["outbounds"], list):
        for sub_outbound in item["outbounds"]:
            if sub_outbound.get("protocol") in ["vless", "vmess", "trojan"]:
                link = generate_vless_vmess_url(sub_outbound, local_remark, index)
                if link: extracted_links.append(link)
    
    elif "protocol" in item:
        if item.get("protocol") in ["vless", "vmess", "trojan"]:
            link = generate_vless_vmess_url(item, local_remark, index)
            if link: extracted_links.append(link)
            
    return extracted_links

def processing_thread(content):
    try:
        print("--- STARTING PROCESSING ---")
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            print("Invalid JSON structure")
            update_status("ERROR: INVALID JSON STRUCTURE", "red")
            messagebox.showerror("ERROR", "INVALID JSON FORMAT!")
            return

        items_to_process = []
        if isinstance(data, dict):
            items_to_process = [data]
        elif isinstance(data, list):
            items_to_process = data
        else:
            print("Unknown Data Type")
            return

        final_links = []
        for i, item in enumerate(items_to_process):
            if isinstance(item, dict):
                links = process_single_item(item, i)
                final_links.extend(links)
        
        if not final_links:
            update_status("NO CONFIGS FOUND", "red")
            messagebox.showwarning("RESULT", "NO VALID CONFIGS FOUND.")
            return

        result_text = "\n".join(final_links)
        root.after(0, lambda: display_result(result_text, len(final_links)))
        print(f"Successfully extracted {len(final_links)} links.")

    except Exception as e:
        print("CRITICAL ERROR IN THREAD:")
        traceback.print_exc()
        update_status(f"ERROR: {str(e).upper()}", "red")

def display_result(text, count):
    entry_output.config(state='normal', bg="white", fg="black")
    entry_output.delete("1.0", tk.END)
    entry_output.insert("1.0", text)
    entry_output.config(state='disabled')
    status_label.config(text=f"SUCCESS! {count} CONFIGS EXTRACTED.", fg="#00ff00")

def update_status(text, color):
    root.after(0, lambda: status_label.config(text=text, fg=color))

# --- Button Actions ---

def on_convert_click():
    content = text_input.get("1.0", tk.END).strip()
    if not content:
        messagebox.showwarning("WARNING", "PLEASE PASTE JSON FIRST!")
        return
    
    status_label.config(text="PROCESSING...", fg="yellow")
    threading.Thread(target=processing_thread, args=(content,), daemon=True).start()

def fetch_from_url_thread(url):
    try:
        print(f"Downloading from: {url}")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
            content = response.read().decode('utf-8', errors='ignore')
        
        print("Download complete.")
        root.after(0, lambda: text_input.delete("1.0", tk.END))
        root.after(0, lambda: text_input.insert("1.0", content))
        
        processing_thread(content)
        
    except Exception as e:
        print("DOWNLOAD ERROR:")
        traceback.print_exc()
        update_status("DOWNLOAD FAILED", "red")
        root.after(0, lambda: messagebox.showerror("DOWNLOAD ERROR", f"CHECK CMD FOR DETAILS.\n{str(e)}"))

def on_url_click():
    url = simpledialog.askstring("IMPORT URL", "ENTER SUBSCRIPTION/FILE URL:")
    if not url: return
    status_label.config(text="DOWNLOADING...", fg="yellow")
    threading.Thread(target=fetch_from_url_thread, args=(url,), daemon=True).start()

def clear_all():
    text_input.delete("1.0", tk.END)
    entry_output.config(state='normal', bg="white")
    entry_output.delete("1.0", tk.END)
    entry_output.config(state='disabled')
    status_label.config(text="CLEARED.", fg="white")

def copy_to_clipboard():
    link = entry_output.get("1.0", tk.END).strip()
    if link:
        root.clipboard_clear()
        root.clipboard_append(link)
        status_label.config(text="ALL LINKS COPIED!", fg="#00ffff")

# --- GUI Setup ---

if __name__ == "__main__":
    print("-" * 50)
    print("VIP3R CONVERTER STARTED")
    print("LOGS WILL APPEAR HERE...")
    print("-" * 50)

    root = tk.Tk()
    root.title("IRJSON_TO")
    root.geometry("500x700")
    root.configure(bg="#1e1e1e")
    root.resizable(False, False)

    BG = "#1e1e1e"
    FG = "#ffffff"
    ACCENT = "#00ff00" 

    # Header
    tk.Label(root, text="V I P 3 R", font=("Consolas", 24, "bold"), bg=BG, fg=ACCENT).pack(pady=(20, 5))
    tk.Label(root, text="IRJSON_TO (ADVANCED VERSION)", font=("Arial", 10), bg=BG, fg="#666666").pack(pady=(0, 15))

    # Top Buttons Frame
    frame_top_btns = tk.Frame(root, bg=BG)
    frame_top_btns.pack(fill=tk.X, padx=20)

    btn_url = tk.Button(frame_top_btns, text="🌐 IMPORT URL", command=on_url_click, 
                        font=("Arial", 9, "bold"), bg="#007acc", fg="white", relief="flat", width=20)
    btn_url.pack(side=tk.LEFT, padx=5)

    btn_clear = tk.Button(frame_top_btns, text="🗑 CLEAR", command=clear_all, 
                          font=("Arial", 9, "bold"), bg="#ff4444", fg="white", relief="flat", width=20)
    btn_clear.pack(side=tk.RIGHT, padx=5)

    # Input
    tk.Label(root, text="PASTE JSON CONFIG BELOW:", font=("Arial", 9, "bold"), bg=BG, fg="#cccccc").pack(pady=(10, 5))
    text_input = tk.Text(root, height=10, bg="#2d2d2d", fg=FG, borderwidth=0, font=("Consolas", 9))
    text_input.pack(padx=20, fill=tk.X)

    # Convert
    tk.Button(root, text="CONVERT TO LINKS", command=on_convert_click, 
              font=("Arial", 11, "bold"), bg=ACCENT, fg="black", relief="flat", pady=5).pack(pady=15, fill=tk.X, padx=50)

    # Output
    tk.Label(root, text="NORMAL LINKS (BATCH RESULT):", font=("Arial", 9, "bold"), bg=BG, fg="#cccccc").pack(pady=5)
    entry_output = tk.Text(root, height=10, bg="white", fg="black", borderwidth=0, font=("Consolas", 9), state='disabled')
    entry_output.pack(padx=20, fill=tk.X)

    # Copy
    tk.Button(root, text="COPY ALL LINKS", command=copy_to_clipboard, 
              font=("Arial", 10), bg="#333333", fg="white", relief="flat").pack(pady=10)

    status_label = tk.Label(root, text="READY", bg=BG, fg="#666666", font=("Arial", 8))
    status_label.pack(side=tk.BOTTOM, pady=10)

    root.mainloop()