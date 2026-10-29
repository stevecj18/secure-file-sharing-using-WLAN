import os
import sys
import time
import socket
import tempfile
import threading
import subprocess
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

import config
import crypto_utils
import network_utils
import auth

class ReceiverGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure WLAN File Sharing — Receiver")
        self.root.geometry("800x700")
        self.root.minsize(720, 620)

        # Color Palette & Theme
        self.BG_COLOR = "#0f172a"        # Deep slate dark background
        self.CARD_BG = "#1e293b"         # Slate card background
        self.ACCENT_BLUE = "#38bdf8"     # Electric blue
        self.ACCENT_GREEN = "#22c55e"    # Emerald green
        self.ACCENT_RED = "#ef4444"      # Crimson red
        self.ACCENT_PURPLE = "#a855f7"   # Purple accent
        self.TEXT_MAIN = "#f8fafc"       # White text
        self.TEXT_MUTED = "#94a3b8"      # Light slate text
        self.ENTRY_BG = "#0f172a"        # Entry box background

        self.root.configure(bg=self.BG_COLOR)

        # Server state
        self.server_socket: Optional[socket.socket] = None
        self.is_running = False
        self.server_thread: Optional[threading.Thread] = None

        # Load RSA Key Pair
        self._log_init("Initializing Cryptographic Security Subsystem...")
        self.private_pem, self.public_pem = crypto_utils.load_or_create_rsa_keys()
        
        # Build UI Components
        self._setup_styles()
        self._create_header()
        self._create_server_control_card()
        self._create_transfer_info_card()
        self._create_verification_card()
        self._create_log_card()

        self._log("RSA 2048-bit Private/Public Keypair loaded successfully.", "SECURE")
        self._log("Receiver security subsystem ready. Click 'Start Server' to listen.", "INFO")

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TProgressbar",
                        thickness=18,
                        troughcolor="#0f172a",
                        background=self.ACCENT_GREEN,
                        borderwidth=0)

    def _create_header(self):
        header_frame = tk.Frame(self.root, bg=self.BG_COLOR, pady=12)
        header_frame.pack(fill="x", padx=20)

        title_label = tk.Label(header_frame,
                               text="📥 Secure WLAN File Sharing — Receiver",
                               font=("Segoe UI", 16, "bold"),
                               fg=self.ACCENT_GREEN,
                               bg=self.BG_COLOR)
        title_label.pack(anchor="w")

        subtitle_label = tk.Label(header_frame,
                                  text="Server Listening Mode — RSA Session Decryption & AES-GCM/SHA-256 Validation",
                                  font=("Segoe UI", 9),
                                  fg=self.TEXT_MUTED,
                                  bg=self.BG_COLOR)
        subtitle_label.pack(anchor="w")

    def _create_server_control_card(self):
        card = tk.LabelFrame(self.root,
                             text=" Server Network Configuration ",
                             font=("Segoe UI", 10, "bold"),
                             fg=self.ACCENT_GREEN,
                             bg=self.CARD_BG,
                             bd=1,
                             relief="solid",
                             padx=15,
                             pady=12)
        card.pack(fill="x", padx=20, pady=5)

        row = tk.Frame(card, bg=self.CARD_BG)
        row.pack(fill="x")

        # Local IP Display
        self.local_ip = network_utils.get_local_ip()
        tk.Label(row, text="Receiver IPv4:", font=("Segoe UI", 9, "bold"), fg=self.TEXT_MAIN, bg=self.CARD_BG).pack(side="left")
        
        ip_badge = tk.Label(row, text=f" {self.local_ip} ", font=("Segoe UI", 10, "bold"), fg=self.ACCENT_BLUE, bg="#0f172a", bd=1, relief="solid")
        ip_badge.pack(side="left", padx=(5, 20))

        # Port Input
        tk.Label(row, text="Port:", font=("Segoe UI", 9, "bold"), fg=self.TEXT_MAIN, bg=self.CARD_BG).pack(side="left")
        self.port_entry = tk.Entry(row, font=("Segoe UI", 10), bg=self.ENTRY_BG, fg=self.TEXT_MAIN, insertbackground=self.TEXT_MAIN, bd=1, relief="solid", width=8)
        self.port_entry.insert(0, str(config.DEFAULT_PORT))
        self.port_entry.pack(side="left", padx=(5, 20))

        # Start / Stop Server Button
        self.toggle_btn = tk.Button(row,
                                    text="▶ Start Server",
                                    command=self._toggle_server,
                                    font=("Segoe UI", 10, "bold"),
                                    bg=self.ACCENT_GREEN,
                                    fg="#0f172a",
                                    activebackground="#16a34a",
                                    activeforeground="#ffffff",
                                    padx=15,
                                    pady=4,
                                    bd=0,
                                    cursor="hand2")
        self.toggle_btn.pack(side="right")

    def _create_transfer_info_card(self):
        card = tk.LabelFrame(self.root,
                             text=" Active Connection & Transfer Status ",
                             font=("Segoe UI", 10, "bold"),
                             fg=self.ACCENT_GREEN,
                             bg=self.CARD_BG,
                             bd=1,
                             relief="solid",
                             padx=15,
                             pady=10)
        card.pack(fill="x", padx=20, pady=5)

        # Info labels
        info_row = tk.Frame(card, bg=self.CARD_BG)
        info_row.pack(fill="x", pady=2)

        self.sender_info_label = tk.Label(info_row,
                                          text="Sender: Disconnected",
                                          font=("Segoe UI", 9, "bold"),
                                          fg=self.TEXT_MUTED,
                                          bg=self.CARD_BG,
                                          anchor="w")
        self.sender_info_label.pack(side="left", fill="x", expand=True)

        self.file_info_label = tk.Label(info_row,
                                        text="File: None",
                                        font=("Segoe UI", 9, "bold"),
                                        fg=self.TEXT_MUTED,
                                        bg=self.CARD_BG,
                                        anchor="e")
        self.file_info_label.pack(side="right", fill="x", expand=True)

        # Progress bar
        prog_frame = tk.Frame(card, bg=self.CARD_BG)
        prog_frame.pack(fill="x", pady=(8, 0))

        self.progress_bar = ttk.Progressbar(prog_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", side="top")

        self.progress_label = tk.Label(prog_frame,
                                       text="Idle",
                                       font=("Segoe UI", 9),
                                       fg=self.TEXT_MUTED,
                                       bg=self.CARD_BG)
        self.progress_label.pack(side="right", pady=2)

    def _create_verification_card(self):
        card = tk.LabelFrame(self.root,
                             text=" Security Verification & Storage ",
                             font=("Segoe UI", 10, "bold"),
                             fg=self.ACCENT_GREEN,
                             bg=self.CARD_BG,
                             bd=1,
                             relief="solid",
                             padx=15,
                             pady=10)
        card.pack(fill="x", padx=20, pady=5)

        badges_frame = tk.Frame(card, bg=self.CARD_BG)
        badges_frame.pack(side="left", fill="x", expand=True)

        self.lbl_auth = self._create_badge(badges_frame, "Auth: Idle")
        self.lbl_rsa = self._create_badge(badges_frame, "RSA Key Decrypt: Idle")
        self.lbl_gcm = self._create_badge(badges_frame, "AES-GCM Auth Tag: Idle")
        self.lbl_sha = self._create_badge(badges_frame, "SHA-256 Hash: Idle")

        self.open_folder_btn = tk.Button(card,
                                         text="📂 Open Received Files",
                                         command=self._open_received_folder,
                                         font=("Segoe UI", 9, "bold"),
                                         bg="#334155",
                                         fg=self.TEXT_MAIN,
                                         activebackground="#475569",
                                         activeforeground=self.TEXT_MAIN,
                                         padx=10,
                                         pady=4,
                                         bd=0,
                                         cursor="hand2")
        self.open_folder_btn.pack(side="right")

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
        lbl.pack(side="left", padx=3)
        return lbl

    def _create_log_card(self):
        card = tk.LabelFrame(self.root,
                             text=" Security Audit Log ",
                             font=("Segoe UI", 10, "bold"),
                             fg=self.ACCENT_GREEN,
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

    def _log_init(self, message: str):
        # Helper for initial setup before log_area exists
        pass

    def _log(self, message: str, level: str = "INFO"):
        timestamp = time.strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}] "
        if hasattr(self, 'log_area'):
            self.log_area.config(state="normal")
            self.log_area.insert(tk.END, prefix + message + "\n")
            self.log_area.see(tk.END)
            self.log_area.config(state="disabled")

    def _toggle_server(self):
        if not self.is_running:
            self._start_server()
        else:
            self._stop_server()

    def _start_server(self):
        port_str = self.port_entry.get().strip()
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Port must be a valid integer between 1 and 65535.")
            return

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((config.DEFAULT_HOST, port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0) # Allows periodic loop checking for stop flag
            
            self.is_running = True
            self.toggle_btn.config(text="⏹ Stop Server", bg=self.ACCENT_RED, activebackground="#dc2626")
            self.port_entry.config(state="disabled")

            self._log(f"Server STARTED. Listening on 0.0.0.0:{port} (Local WLAN IP: {self.local_ip})", "SUCCESS")
            
            # Start background accept loop thread
            self.server_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.server_thread.start()

        except Exception as e:
            self._log(f"Failed to start server: {str(e)}", "ERROR")
            messagebox.showerror("Server Error", f"Could not start server on port {port}:\n{str(e)}")

    def _stop_server(self):
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

        self.toggle_btn.config(text="▶ Start Server", bg=self.ACCENT_GREEN, activebackground="#16a34a")
        self.port_entry.config(state="normal")
        self._log("Server STOPPED.", "INFO")

    def _listen_loop(self):
        while self.is_running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                client_sock.settimeout(config.SOCKET_TIMEOUT)
                self._log(f"Incoming connection accepted from {client_addr[0]}:{client_addr[1]}")
                
                # Handle client request in a dedicated handler thread
                client_thread = threading.Thread(target=self._handle_client,
                                                 args=(client_sock, client_addr),
                                                 daemon=True)
                client_thread.start()
            except socket.timeout:
                continue
            except Exception:
                if self.is_running:
                    self._log("Server socket error occurred.", "ERROR")
                break

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple):
        temp_enc_path = None
        temp_dec_path = None
        try:
            # Step 1: Receive & Verify Authentication
            auth_msg = network_utils.recv_json_message(client_sock)
            if auth_msg.get("action") != "AUTH":
                network_utils.send_json_message(client_sock, {"status": "AUTH_FAILED", "message": "Expected AUTH request"})
                return

            username = auth_msg.get("username", "")
            password = auth_msg.get("password", "")

            self.root.after(0, lambda: self.sender_info_label.config(text=f"Sender: {username} ({client_addr[0]})", fg=self.ACCENT_BLUE))
            self.root.after(0, lambda: self.lbl_auth.config(text="Auth: Verifying...", fg=self.ACCENT_BLUE))

            if not auth.authenticate_user(username, password):
                self._log(f"AUTHENTICATION FAILED for user '{username}' from {client_addr[0]}!", "ALERT")
                self.root.after(0, lambda: self.lbl_auth.config(text="Auth: Rejected", fg=self.ACCENT_RED))
                network_utils.send_json_message(client_sock, {"status": "AUTH_FAILED", "message": "Invalid username or password"})
                return

            self._log(f"User '{username}' AUTHENTICATED successfully.", "SUCCESS")
            self.root.after(0, lambda: self.lbl_auth.config(text="Auth: Passed", fg=self.ACCENT_GREEN))

            # Send Public Key to Sender
            public_pem_str = self.public_pem.decode('utf-8')
            network_utils.send_json_message(client_sock, {
                "status": "AUTH_OK",
                "public_key": public_pem_str
            })

            # Step 2: Receive Transfer Metadata
            meta_msg = network_utils.recv_json_message(client_sock)
            if meta_msg.get("action") != "TRANSFER":
                raise ValueError("Expected TRANSFER action metadata.")

            raw_filename = meta_msg.get("filename", "received_file")
            enc_filesize = meta_msg.get("enc_filesize", 0)
            raw_filesize = meta_msg.get("raw_filesize", 0)
            enc_aes_key_hex = meta_msg.get("encrypted_aes_key", "")
            nonce_hex = meta_msg.get("nonce", "")
            tag_hex = meta_msg.get("tag", "")
            expected_sha256 = meta_msg.get("sha256", "")

            safe_filename = network_utils.sanitize_filename(raw_filename)
            self.root.after(0, lambda: self.file_info_label.config(text=f"File: {safe_filename} ({self._format_size(raw_filesize)})", fg=self.TEXT_MAIN))

            self._log(f"Transfer Metadata Received: '{safe_filename}' (Encrypted size: {enc_filesize:,} bytes)")
            
            # Step 3: Decrypt AES Session Key using Receiver's Private RSA Key
            self._log("Decrypting AES session key using Receiver's RSA Private Key (RSA-OAEP)...")
            self.root.after(0, lambda: self.lbl_rsa.config(text="RSA Decrypt: In Progress", fg=self.ACCENT_BLUE))

            encrypted_aes_key = bytes.fromhex(enc_aes_key_hex)
            nonce = bytes.fromhex(nonce_hex)
            tag = bytes.fromhex(tag_hex)

            aes_session_key = crypto_utils.decrypt_aes_key_rsa(self.private_pem, encrypted_aes_key)
            self._log("RSA Session Key Decryption SUCCESSFUL. 256-bit AES key recovered.", "SECURE")
            self.root.after(0, lambda: self.lbl_rsa.config(text="RSA Decrypt: Success", fg=self.ACCENT_GREEN))

            # Acknowledge metadata ready
            network_utils.send_json_message(client_sock, {"status": "READY_FOR_DATA"})

            # Step 4: Stream Encrypted Payload from Socket to Temporary File
            self._log("Receiving encrypted data stream over TCP socket...")
            
            with tempfile.NamedTemporaryFile(delete=False) as temp_enc:
                temp_enc_path = temp_enc.name
                received_bytes = 0
                start_time = time.time()

                while received_bytes < enc_filesize:
                    to_read = min(config.CHUNK_SIZE, enc_filesize - received_bytes)
                    chunk = network_utils.recv_exact(client_sock, to_read)
                    temp_enc.write(chunk)
                    received_bytes += len(chunk)

                    percentage = (received_bytes / enc_filesize) * 100
                    elapsed = time.time() - start_time
                    speed_kbps = (received_bytes / 1024) / max(elapsed, 0.001)

                    self.root.after(0, lambda p=percentage, r=received_bytes, t=enc_filesize, sp=speed_kbps:
                                    self._update_progress(p, r, t, sp))

            self._log(f"Received all {received_bytes:,} encrypted bytes. Starting AES-GCM tag verification...")
            self.root.after(0, lambda: self.lbl_gcm.config(text="AES-GCM Tag: Verifying...", fg=self.ACCENT_BLUE))

            # Step 5: Streaming AES-GCM Decryption & Tag Authentication Verification
            decryptor = crypto_utils.StreamingAESGCMDecryptor(aes_session_key, nonce, tag)

            with tempfile.NamedTemporaryFile(delete=False) as temp_dec:
                temp_dec_path = temp_dec.name
                with open(temp_enc_path, "rb") as enc_file:
                    while True:
                        chunk = enc_file.read(config.CHUNK_SIZE)
                        if not chunk:
                            break
                        dec_chunk = decryptor.update(chunk)
                        temp_dec.write(dec_chunk)

                # Finalize checks tag authenticity!
                final_dec_chunk = decryptor.finalize()
                temp_dec.write(final_dec_chunk)

            self._log("AES-GCM Authentication Tag VERIFIED! (No ciphertext tampering detected)", "SECURE")
            self.root.after(0, lambda: self.lbl_gcm.config(text="AES-GCM Tag: Passed", fg=self.ACCENT_GREEN))

            # Step 6: SHA-256 File Integrity Check
            self._log("Calculating SHA-256 hash digest of decrypted file...")
            self.root.after(0, lambda: self.lbl_sha.config(text="SHA-256: Verifying...", fg=self.ACCENT_BLUE))

            calculated_sha256 = crypto_utils.calculate_sha256(temp_dec_path)
            self._log(f"Calculated SHA-256 : {calculated_sha256}")
            self._log(f"Expected SHA-256   : {expected_sha256}")

            if calculated_sha256.lower() != expected_sha256.lower():
                raise ValueError(f"SHA-256 Hash Mismatch! Expected {expected_sha256}, got {calculated_sha256}")

            self._log("SHA-256 File Integrity Check MATCHED!", "SECURE")
            self.root.after(0, lambda: self.lbl_sha.config(text="SHA-256: Passed", fg=self.ACCENT_GREEN))

            # Step 7: Move to Final received_files/ Directory
            destination_path = network_utils.get_safe_filepath(config.RECEIVED_FILES_DIR, safe_filename)
            
            # Atomic file move/copy
            with open(temp_dec_path, "rb") as src, open(destination_path, "wb") as dst:
                while True:
                    buf = src.read(config.CHUNK_SIZE)
                    if not buf:
                        break
                    dst.write(buf)

            self._log(f"🎉 FILE SAVED SUCCESSFULLY: '{destination_path.name}' -> {destination_path}", "SUCCESS")
            
            # Notify Sender
            network_utils.send_json_message(client_sock, {
                "status": "SUCCESS",
                "message": "File received, authenticated, and verified."
            })

            self.root.after(0, lambda: messagebox.showinfo("File Received", f"Received and verified file:\n\n{destination_path.name}\n\nSaved to received_files folder."))

        except crypto_utils.InvalidTag:
            self._log("CRITICAL SECURITY ALERT: AES-GCM Authentication Tag Verification Failed! Data was tampered with or corrupted.", "ALERT")
            self.root.after(0, lambda: self.lbl_gcm.config(text="AES-GCM Tag: FAILED", fg=self.ACCENT_RED))
            try:
                network_utils.send_json_message(client_sock, {"status": "CRYPTO_FAILED", "message": "AES-GCM Tag Verification Failed"})
            except Exception:
                pass

        except Exception as e:
            self._log(f"TRANSFER ERROR: {str(e)}", "ERROR")
            try:
                network_utils.send_json_message(client_sock, {"status": "ERROR", "message": str(e)})
            except Exception:
                pass
        finally:
            # Clean up temporary files safely
            for t_path in [temp_enc_path, temp_dec_path]:
                if t_path and os.path.exists(t_path):
                    try:
                        os.remove(t_path)
                    except Exception:
                        pass
            try:
                client_sock.close()
            except Exception:
                pass

    def _update_progress(self, percentage: float, recv: int, total: int, speed_kbps: float):
        self.progress_bar['value'] = percentage
        speed_str = f"{speed_kbps:.1f} KB/s" if speed_kbps < 1024 else f"{(speed_kbps/1024):.2f} MB/s"
        self.progress_label.config(text=f"{percentage:.1f}% ({self._format_size(recv)} / {self._format_size(total)}) @ {speed_str}")

    def _format_size(self, bytes_size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} TB"

    def _open_received_folder(self):
        folder = config.RECEIVED_FILES_DIR
        try:
            if sys.platform == "win32":
                os.startfile(folder)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except Exception as e:
            messagebox.showerror("Folder Error", f"Could not open folder:\n{str(e)}")

def main():
    root = tk.Tk()
    app = ReceiverGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
