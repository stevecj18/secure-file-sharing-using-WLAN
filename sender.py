import os
import sys
import time
import socket
import tempfile
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import config
import crypto_utils
import network_utils
import auth

class SenderGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure WLAN File Sharing — Sender")
        self.root.geometry("780x680")
        self.root.minsize(700, 600)
        
        # Color Palette & Styles
        self.BG_COLOR = "#0f172a"        # Deep slate dark background
        self.CARD_BG = "#1e293b"         # Slate card background
        self.ACCENT_BLUE = "#38bdf8"     # Electric blue
        self.ACCENT_GREEN = "#22c55e"    # Emerald green
        self.ACCENT_RED = "#ef4444"      # Crimson red
        self.TEXT_MAIN = "#f8fafc"       # Pure white text
        self.TEXT_MUTED = "#94a3b8"      # Light slate text
        self.ENTRY_BG = "#0f172a"        # Dark entry box background

        self.root.configure(bg=self.BG_COLOR)
        
        # Selected File state
        self.selected_file_path: Optional[str] = None
        self.is_transferring = False
        
        # Build UI Components
        self._setup_styles()
        self._create_header()
        self._create_network_card()
        self._create_file_card()
        self._create_status_card()
        self._create_log_card()
        
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("TProgressbar",
                        thickness=18,
                        troughcolor="#0f172a",
                        background=self.ACCENT_BLUE,
                        borderwidth=0)
        
    def _create_header(self):
        header_frame = tk.Frame(self.root, bg=self.BG_COLOR, pady=12)
        header_frame.pack(fill="x", padx=20)
        
        title_label = tk.Label(header_frame,
                               text="🔒 Secure WLAN File Sharing — Sender",
                               font=("Segoe UI", 16, "bold"),
                               fg=self.ACCENT_BLUE,
                               bg=self.BG_COLOR)
        title_label.pack(anchor="w")
        
        subtitle_label = tk.Label(header_frame,
                                  text="Hybrid Encryption: AES-256-GCM + RSA-2048 OAEP + SHA-256 Integrity",
                                  font=("Segoe UI", 9),
                                  fg=self.TEXT_MUTED,
                                  bg=self.BG_COLOR)
        subtitle_label.pack(anchor="w")

    def _create_network_card(self):
        card = tk.LabelFrame(self.root,
                             text=" Receiver Connection & Authentication ",
                             font=("Segoe UI", 10, "bold"),
                             fg=self.ACCENT_BLUE,
                             bg=self.CARD_BG,
                             bd=1,
                             relief="solid",
                             padx=15,
                             pady=12)
        card.pack(fill="x", padx=20, pady=5)

        # Receiver IP & Port
        row1 = tk.Frame(card, bg=self.CARD_BG)
        row1.pack(fill="x", pady=4)
        
        tk.Label(row1, text="Receiver IP:", font=("Segoe UI", 9, "bold"), fg=self.TEXT_MAIN, bg=self.CARD_BG, width=12, anchor="w").pack(side="left")
        self.ip_entry = tk.Entry(row1, font=("Segoe UI", 10), bg=self.ENTRY_BG, fg=self.TEXT_MAIN, insertbackground=self.TEXT_MAIN, bd=1, relief="solid")
        self.ip_entry.insert(0, network_utils.get_local_ip())
        self.ip_entry.pack(side="left", fill="x", expand=True, padx=(0, 15))

        tk.Label(row1, text="Port:", font=("Segoe UI", 9, "bold"), fg=self.TEXT_MAIN, bg=self.CARD_BG, width=6, anchor="w").pack(side="left")
        self.port_entry = tk.Entry(row1, font=("Segoe UI", 10), bg=self.ENTRY_BG, fg=self.TEXT_MAIN, insertbackground=self.TEXT_MAIN, bd=1, relief="solid", width=8)
        self.port_entry.insert(0, str(config.DEFAULT_PORT))
        self.port_entry.pack(side="left")

        # Credentials (Username & Password)
        row2 = tk.Frame(card, bg=self.CARD_BG)
        row2.pack(fill="x", pady=4)
        
        tk.Label(row2, text="Username:", font=("Segoe UI", 9, "bold"), fg=self.TEXT_MAIN, bg=self.CARD_BG, width=12, anchor="w").pack(side="left")
        self.user_entry = tk.Entry(row2, font=("Segoe UI", 10), bg=self.ENTRY_BG, fg=self.TEXT_MAIN, insertbackground=self.TEXT_MAIN, bd=1, relief="solid")
        self.user_entry.insert(0, config.DEFAULT_USERNAME)
        self.user_entry.pack(side="left", fill="x", expand=True, padx=(0, 15))

        tk.Label(row2, text="Password:", font=("Segoe UI", 9, "bold"), fg=self.TEXT_MAIN, bg=self.CARD_BG, width=8, anchor="w").pack(side="left")
        self.pass_entry = tk.Entry(row2, font=("Segoe UI", 10), bg=self.ENTRY_BG, fg=self.TEXT_MAIN, insertbackground=self.TEXT_MAIN, show="•", bd=1, relief="solid", width=14)
        self.pass_entry.insert(0, config.DEFAULT_PASSWORD)
        self.pass_entry.pack(side="left")

    def _create_file_card(self):
        card = tk.LabelFrame(self.root,
                             text=" File Selection & Transfer Action ",
                             font=("Segoe UI", 10, "bold"),
                             fg=self.ACCENT_BLUE,
                             bg=self.CARD_BG,
                             bd=1,
                             relief="solid",
                             padx=15,
                             pady=12)
        card.pack(fill="x", padx=20, pady=5)

        row = tk.Frame(card, bg=self.CARD_BG)
        row.pack(fill="x")

        self.browse_btn = tk.Button(row,
                                   text="📁 Browse File...",
                                   command=self._select_file,
                                   font=("Segoe UI", 9, "bold"),
                                   bg="#334155",
                                   fg=self.TEXT_MAIN,
                                   activebackground="#475569",
                                   activeforeground=self.TEXT_MAIN,
                                   padx=12,
                                   pady=4,
                                   bd=0,
                                   cursor="hand2")
        self.browse_btn.pack(side="left", padx=(0, 10))

        self.file_info_label = tk.Label(row,
                                        text="No file selected",
                                        font=("Segoe UI", 9),
                                        fg=self.TEXT_MUTED,
                                        bg=self.CARD_BG,
                                        anchor="w")
        self.file_info_label.pack(side="left", fill="x", expand=True)

        self.send_btn = tk.Button(row,
                                 text="🚀 Send File Securely",
                                 command=self._start_send_thread,
                                 font=("Segoe UI", 10, "bold"),
                                 bg=self.ACCENT_BLUE,
                                 fg="#0f172a",
                                 activebackground="#0284c7",
                                 activeforeground="#ffffff",
                                 padx=15,
                                 pady=5,
                                 bd=0,
                                 cursor="hand2",
                                 state="disabled")
        self.send_btn.pack(side="right")

    def _create_status_card(self):
        card = tk.LabelFrame(self.root,
                             text=" Security & Transfer Status ",
                             font=("Segoe UI", 10, "bold"),
                             fg=self.ACCENT_BLUE,
                             bg=self.CARD_BG,
                             bd=1,
                             relief="solid",
                             padx=15,
                             pady=10)
        card.pack(fill="x", padx=20, pady=5)

        # Status Badges Frame
        badges_frame = tk.Frame(card, bg=self.CARD_BG)
        badges_frame.pack(fill="x", pady=2)

        self.lbl_conn = self._create_badge(badges_frame, "Connection: Idle")
        self.lbl_crypto = self._create_badge(badges_frame, "Encryption: AES-256-GCM + RSA")
        self.lbl_hash = self._create_badge(badges_frame, "Integrity: SHA-256 Ready")

        # Progress Bar & Info
        prog_frame = tk.Frame(card, bg=self.CARD_BG)
        prog_frame.pack(fill="x", pady=(8, 0))

        self.progress_bar = ttk.Progressbar(prog_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", side="top")

        self.progress_label = tk.Label(prog_frame,
                                       text="0% (0 KB / 0 KB)",
                                       font=("Segoe UI", 9),
                                       fg=self.TEXT_MUTED,
                                       bg=self.CARD_BG)
        self.progress_label.pack(side="right", pady=2)

    def _create_badge(self, parent, text):
        lbl = tk.Label(parent,
                       text=text,
                       font=("Segoe UI", 8, "bold"),
                       fg=self.TEXT_MUTED,
                       bg="#0f172a",
                       padx=8,
                       pady=3,
                       bd=1,
                       relief="solid")
        lbl.pack(side="left", padx=4)
        return lbl

    def _create_log_card(self):
        card = tk.LabelFrame(self.root,
                             text=" Security Audit Log ",
                             font=("Segoe UI", 10, "bold"),
                             fg=self.ACCENT_BLUE,
                             bg=self.CARD_BG,
                             bd=1,
                             relief="solid",
                             padx=10,
                             pady=8)
        card.pack(fill="both", expand=True, padx=20, pady=(5, 15))

        self.log_area = scrolledtext.ScrolledText(card,
                                                   font=("Consolas", 9),
                                                   bg=self.ENTRY_BG,
                                                   fg="#cbd5e1",
                                                   insertbackground=self.TEXT_MAIN,
                                                   bd=0,
                                                   height=8)
        self.log_area.pack(fill="both", expand=True)

    def _log(self, message: str, level: str = "INFO"):
        timestamp = time.strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}] "
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, prefix + message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state="disabled")

    def _select_file(self):
        path = filedialog.askopenfilename(title="Select File to Send")
        if path:
            self.selected_file_path = path
            size_bytes = os.path.getsize(path)
            size_str = self._format_size(size_bytes)
            filename = os.path.basename(path)
            self.file_info_label.config(text=f"Selected: {filename} ({size_str})", fg=self.ACCENT_GREEN)
            self.send_btn.config(state="normal")
            self._log(f"Selected file for transfer: {filename} ({size_bytes:,} bytes)")

    def _format_size(self, bytes_size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} TB"

    def _start_send_thread(self):
        if not self.selected_file_path or not os.path.exists(self.selected_file_path):
            messagebox.showerror("Error", "Please select a valid file to send.")
            return

        ip = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()
        username = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()

        if not ip or not port_str or not username or not password:
            messagebox.showerror("Error", "All connection and authentication fields are required.")
            return

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Port must be a valid integer between 1 and 65535.")
            return

        self.is_transferring = True
        self.send_btn.config(state="disabled")
        self.browse_btn.config(state="disabled")
        
        # Reset progress bar
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Initializing transfer...", fg=self.TEXT_MUTED)

        # Launch background execution thread
        threading.Thread(target=self._send_file_worker,
                         args=(ip, port, username, password, self.selected_file_path),
                         daemon=True).start()

    def _send_file_worker(self, ip: str, port: int, username: str, password: str, file_path: str):
        temp_enc_path = None
        sock = None
        try:
            # 1. Network Connection
            self.root.after(0, lambda: self.lbl_conn.config(text="Connection: Connecting...", fg=self.ACCENT_BLUE))
            self._log(f"Connecting to receiver at {ip}:{port}...")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.SOCKET_TIMEOUT)
            sock.connect((ip, port))
            
            self.root.after(0, lambda: self.lbl_conn.config(text="Connection: Connected", fg=self.ACCENT_GREEN))
            self._log(f"TCP socket established with {ip}:{port}.")

            # 2. Authentication Handshake
            self._log(f"Authenticating user '{username}'...")
            auth_req = {
                "action": "AUTH",
                "username": username,
                "password": password,
                "version": config.PROTOCOL_VERSION
            }
            network_utils.send_json_message(sock, auth_req)

            auth_res = network_utils.recv_json_message(sock)
            if auth_res.get("status") != "AUTH_OK":
                err_msg = auth_res.get("message", "Authentication rejected by receiver.")
                raise PermissionError(f"Authentication Failed: {err_msg}")

            receiver_public_pem_str = auth_res.get("public_key")
            if not receiver_public_pem_str:
                raise ValueError("Receiver failed to return RSA public key.")
            
            receiver_public_pem = receiver_public_pem_str.encode('utf-8')
            self._log("Authentication SUCCESS. Receiver RSA Public Key received.")

            # 3. Cryptographic Preparation
            filename = os.path.basename(file_path)
            raw_filesize = os.path.getsize(file_path)
            
            self._log(f"Computing SHA-256 digest of original file '{filename}'...")
            file_sha256 = crypto_utils.calculate_sha256(file_path)
            self._log(f"Original File SHA-256: {file_sha256[:16]}...{file_sha256[-16:]}")
            self.root.after(0, lambda: self.lbl_hash.config(text=f"SHA-256: Verified", fg=self.ACCENT_GREEN))

            self._log("Generating fresh 256-bit AES session key & 96-bit GCM nonce...")
            aes_key = crypto_utils.generate_aes_key()
            nonce = crypto_utils.generate_gcm_nonce()

            self._log("Encrypting AES session key with Receiver's RSA Public Key (RSA-OAEP)...")
            encrypted_aes_key = crypto_utils.encrypt_aes_key_rsa(receiver_public_pem, aes_key)

            # 4. Stream Encrypt File to Temporary Payload
            self._log(f"Encrypting file content using AES-256-GCM...")
            self.root.after(0, lambda: self.lbl_crypto.config(text="Encryption: AES-256-GCM Encrypting", fg=self.ACCENT_BLUE))

            encryptor = crypto_utils.StreamingAESGCMEncryptor(aes_key, nonce)
            
            # Create temp encrypted file
            with tempfile.NamedTemporaryFile(delete=False) as temp_f:
                temp_enc_path = temp_f.name
                with open(file_path, "rb") as orig_f:
                    while True:
                        chunk = orig_f.read(config.CHUNK_SIZE)
                        if not chunk:
                            break
                        enc_chunk = encryptor.update(chunk)
                        temp_f.write(enc_chunk)
                
                final_chunk, tag = encryptor.finalize()
                temp_f.write(final_chunk)

            enc_filesize = os.path.getsize(temp_enc_path)
            self._log(f"AES-GCM Encryption Complete. Auth Tag: {tag.hex()} (Encrypted size: {enc_filesize:,} bytes)")
            self.root.after(0, lambda: self.lbl_crypto.config(text="Encryption: Encrypted (AES+RSA)", fg=self.ACCENT_GREEN))

            # 5. Send Transfer Metadata Header
            metadata = {
                "action": "TRANSFER",
                "filename": filename,
                "enc_filesize": enc_filesize,
                "raw_filesize": raw_filesize,
                "encrypted_aes_key": encrypted_aes_key.hex(),
                "nonce": nonce.hex(),
                "tag": tag.hex(),
                "sha256": file_sha256
            }
            network_utils.send_json_message(sock, metadata)

            meta_res = network_utils.recv_json_message(sock)
            if meta_res.get("status") != "READY_FOR_DATA":
                raise RuntimeError("Receiver rejected transfer metadata header.")

            # 6. Stream Encrypted Data Chunks Over TCP Socket
            self._log("Streaming encrypted file data over WLAN...")
            sent_bytes = 0
            start_time = time.time()

            with open(temp_enc_path, "rb") as enc_f:
                while sent_bytes < enc_filesize:
                    chunk = enc_f.read(config.CHUNK_SIZE)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    sent_bytes += len(chunk)

                    # Update GUI progress
                    percentage = (sent_bytes / enc_filesize) * 100
                    elapsed = time.time() - start_time
                    speed_kbps = (sent_bytes / 1024) / max(elapsed, 0.001)

                    self.root.after(0, lambda p=percentage, s=sent_bytes, t=enc_filesize, sp=speed_kbps:
                                    self._update_progress(p, s, t, sp))

            # 7. Await Final Verification Ack from Receiver
            self._log("File stream upload complete. Waiting for Receiver AES-GCM & SHA-256 verification...")
            final_res = network_utils.recv_json_message(sock)

            if final_res.get("status") == "SUCCESS":
                self._log("🎉 TRANSFER SUCCESS! Receiver decrypted and verified file integrity.", "SUCCESS")
                self.root.after(0, lambda: messagebox.showinfo("Success", f"File '{filename}' transferred and verified successfully!"))
            else:
                err_detail = final_res.get("message", "Receiver verification failed.")
                raise RuntimeError(f"Transfer Failed on Receiver: {err_detail}")

        except Exception as e:
            self._log(f"ERROR: {str(e)}", "ERROR")
            self.root.after(0, lambda err=str(e): self._show_error_dialog(err))
            self.root.after(0, lambda: self.lbl_conn.config(text="Connection: Failed", fg=self.ACCENT_RED))
            self.root.after(0, lambda: self.lbl_crypto.config(text="Encryption: Failed", fg=self.ACCENT_RED))
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            if temp_enc_path and os.path.exists(temp_enc_path):
                try:
                    os.remove(temp_enc_path)
                except Exception:
                    pass
            
            self.is_transferring = False
            self.root.after(0, self._reset_ui_buttons)

    def _update_progress(self, percentage: float, sent: int, total: int, speed_kbps: float):
        self.progress_bar['value'] = percentage
        speed_str = f"{speed_kbps:.1f} KB/s" if speed_kbps < 1024 else f"{(speed_kbps/1024):.2f} MB/s"
        self.progress_label.config(text=f"{percentage:.1f}% ({self._format_size(sent)} / {self._format_size(total)}) @ {speed_str}")

    def _show_error_dialog(self, error_message: str):
        messagebox.showerror("Transfer Failure", f"Transfer failed:\n\n{error_message}")

    def _reset_ui_buttons(self):
        self.send_btn.config(state="normal" if self.selected_file_path else "disabled")
        self.browse_btn.config(state="normal")

def main():
    root = tk.Tk()
    app = SenderGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
