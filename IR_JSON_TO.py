import tkinter as tk
from tkinter import messagebox
import json
import urllib.parse
import base64

# --- Logic Functions ---

def generate_link():
    json_input = text_input.get("1.0", tk.END).strip()
    
    if not json_input:
        messagebox.showwarning("Warning", "Please paste the JSON config first!")
        return

    try:
        data = json.loads(json_input)
    except json.JSONDecodeError:
        messagebox.showerror("Error", "Invalid JSON format!")
        return

    # Get Remark
    remark = data.get("remarks", "VIP3R-Config")
    safe_remark = urllib.parse.quote(remark)

    # Find relevant outbound
    target_outbound = None
    protocol = ""
    
    if "outbounds" in data:
        for outbound in data["outbounds"]:
            proto = outbound.get("protocol")
            if proto in ["vless", "vmess", "trojan"]:
                target_outbound = outbound
                protocol = proto
                break
    
    if not target_outbound:
        messagebox.showerror("Error", "No VLESS, VMess, or Trojan outbound found.")
        return

    try:
        # Common settings
        settings = target_outbound["settings"]
        stream_settings = target_outbound.get("streamSettings", {})
        network = stream_settings.get("network", "tcp")
        security = stream_settings.get("security", "none")
        
        # Extract Server Info
        if protocol in ["vless", "trojan"]:
            vnext = settings.get("vnext", [{}])[0] if "vnext" in settings else settings.get("servers", [{}])[0]
            address = vnext.get("address")
            port = vnext.get("port")
            
            if protocol == "vless":
                uuid_pass = vnext["users"][0]["id"]
            else: # trojan
                uuid_pass = vnext.get("password", [""])[0]

            # Build Params
            params = {"type": network, "security": security}
            
            # WS / GRPC / TCP Headers
            if network == "ws":
                ws_settings = stream_settings.get("wsSettings", {})
                if "path" in ws_settings: params["path"] = ws_settings["path"]
                if "headers" in ws_settings and "Host" in ws_settings["headers"]:
                    params["host"] = ws_settings["headers"]["Host"]
                elif "host" in ws_settings: params["host"] = ws_settings["host"]
            
            elif network == "grpc":
                grpc_settings = stream_settings.get("grpcSettings", {})
                if "serviceName" in grpc_settings: params["serviceName"] = grpc_settings["serviceName"]
                if "mode" in grpc_settings: params["mode"] = grpc_settings["mode"]

            # TLS / Reality
            if security in ["tls", "xtls", "reality"]:
                tls_settings = stream_settings.get("tlsSettings") or stream_settings.get("xtlsSettings") or stream_settings.get("realitySettings") or {}
                if "serverName" in tls_settings: params["sni"] = tls_settings["serverName"]
                if security == "reality":
                    if "publicKey" in tls_settings: params["pbk"] = tls_settings["publicKey"]
                    if "shortIds" in tls_settings: params["sid"] = tls_settings["shortIds"][0]
                    if "fingerprint" in tls_settings: params["fp"] = tls_settings["fingerprint"]
                elif "alpn" in tls_settings:
                    params["alpn"] = ",".join(tls_settings["alpn"])

            query = urllib.parse.urlencode(params)
            final_link = f"{protocol}://{uuid_pass}@{address}:{port}?{query}#{safe_remark}"

        elif protocol == "vmess":
            # VMess uses Base64 encoded JSON
            vnext = settings["vnext"][0]
            address = vnext["address"]
            port = vnext["port"]
            uuid = vnext["users"][0]["id"]
            alterId = vnext["users"][0].get("alterId", 0)

            vmess_dict = {
                "v": "2",
                "ps": remark,
                "add": address,
                "port": port,
                "id": uuid,
                "aid": alterId,
                "net": network,
                "type": "none",
                "host": "",
                "path": "",
                "tls": security if security != "none" else ""
            }

            # Fill specific network details
            if network == "ws":
                ws_settings = stream_settings.get("wsSettings", {})
                vmess_dict["path"] = ws_settings.get("path", "")
                headers = ws_settings.get("headers", {})
                vmess_dict["host"] = headers.get("Host", ws_settings.get("host", ""))
            
            elif network == "grpc":
                 grpc_settings = stream_settings.get("grpcSettings", {})
                 vmess_dict["path"] = grpc_settings.get("serviceName", "")
                 vmess_dict["type"] = grpc_settings.get("mode", "gun")

            if security in ["tls", "reality"]:
                 tls_settings = stream_settings.get("tlsSettings") or stream_settings.get("realitySettings") or {}
                 vmess_dict["sni"] = tls_settings.get("serverName", "")

            # Encode
            json_str = json.dumps(vmess_dict)
            b64_str = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
            final_link = f"vmess://{b64_str}"

        # Output result
        entry_output.config(state='normal', bg="white", fg="black") # Changed colors here
        entry_output.delete(0, tk.END)
        entry_output.insert(0, final_link)
        entry_output.config(state='readonly')
        status_label.config(text=f"Converted to {protocol.upper()}!", fg="#00ff00")

    except Exception as e:
        messagebox.showerror("Error", f"Parsing Error: {str(e)}")

def copy_to_clipboard():
    link = entry_output.get()
    if link:
        root.clipboard_clear()
        root.clipboard_append(link)
        status_label.config(text="Link Copied to Clipboard!", fg="#00ffff")
    else:
        status_label.config(text="Nothing to copy.", fg="red")

# --- GUI Setup ---

root = tk.Tk()
root.title("IRJSON_TO")
root.geometry("500x600")
root.configure(bg="#1e1e1e")
root.resizable(False, False)

# Styles
BG_COLOR = "#1e1e1e"
FG_COLOR = "#ffffff"
ACCENT_COLOR = "#00ff00" # Hacker Green
BUTTON_COLOR = "#333333"

# Header
lbl_header = tk.Label(root, text="V I P 3 R", font=("Consolas", 24, "bold"), bg=BG_COLOR, fg=ACCENT_COLOR)
lbl_header.pack(pady=(20, 10))

# Input Section
lbl_input = tk.Label(root, text="PASTE JSON CONFIG BELOW:", font=("Arial", 10, "bold"), bg=BG_COLOR, fg="#cccccc")
lbl_input.pack(pady=5)

text_input = tk.Text(root, height=15, bg="#2d2d2d", fg=FG_COLOR, borderwidth=0, font=("Consolas", 9))
text_input.pack(padx=20, pady=5, fill=tk.X)

# Convert Button
btn_convert = tk.Button(root, text="CONVERT TO LINK", command=generate_link, 
                        font=("Arial", 12, "bold"), bg=ACCENT_COLOR, fg="black", 
                        relief="flat", pady=5, cursor="hand2")
btn_convert.pack(pady=20, fill=tk.X, padx=50)

# Output Section
lbl_output = tk.Label(root, text="NORMAL LINK (VLESS/VMESS/TROJAN):", font=("Arial", 10, "bold"), bg=BG_COLOR, fg="#cccccc")
lbl_output.pack(pady=5)

# CHANGED HERE: bg="white", fg="black" for readability
entry_output = tk.Entry(root, bg="white", fg="black", borderwidth=0, font=("Consolas", 10), state='readonly')
entry_output.pack(padx=20, pady=5, fill=tk.X, ipady=5)

# Copy Button
btn_copy = tk.Button(root, text="COPY LINK", command=copy_to_clipboard, 
                     font=("Arial", 10), bg=BUTTON_COLOR, fg="white", 
                     relief="flat", cursor="hand2")
btn_copy.pack(pady=10)

# Status Bar
status_label = tk.Label(root, text="Ready", bg=BG_COLOR, fg="#666666", font=("Arial", 8))
status_label.pack(side=tk.BOTTOM, pady=10)

root.mainloop()