import sys
import tkinter as tk
from tkinter import ttk

import config
import sender
import receiver

class LauncherGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure WLAN File Sharing — Launcher")
        self.root.geometry("480x360")
        self.root.resizable(False, False)
        
        self.BG_COLOR = "#0f172a"
        self.CARD_BG = "#1e293b"
        self.ACCENT_BLUE = "#38bdf8"
        self.ACCENT_GREEN = "#22c55e"
        self.TEXT_MAIN = "#f8fafc"
        self.TEXT_MUTED = "#94a3b8"

        self.root.configure(bg=self.BG_COLOR)

        # Header
        frame = tk.Frame(self.root, bg=self.BG_COLOR, pady=20)
        frame.pack(fill="x", padx=20)

        title = tk.Label(frame, text="🔒 Secure WLAN File Sharing", font=("Segoe UI", 16, "bold"), fg=self.ACCENT_BLUE, bg=self.BG_COLOR)
        title.pack()

        subtitle = tk.Label(frame, text="Academic Project — AES-256-GCM + RSA-2048 Hybrid Encryption", font=("Segoe UI", 9), fg=self.TEXT_MUTED, bg=self.BG_COLOR)
        subtitle.pack(pady=(4, 0))

        # Card container
        card = tk.Frame(self.root, bg=self.CARD_BG, bd=1, relief="solid", padx=25, pady=25)
        card.pack(fill="both", expand=True, padx=30, pady=(0, 25))

        lbl = tk.Label(card, text="Select application mode to launch:", font=("Segoe UI", 11, "bold"), fg=self.TEXT_MAIN, bg=self.CARD_BG)
        lbl.pack(pady=(0, 15))

        btn_receiver = tk.Button(card,
                                 text="📥 Launch RECEIVER (Server)",
                                 command=self._launch_receiver,
                                 font=("Segoe UI", 11, "bold"),
                                 bg=self.ACCENT_GREEN,
                                 fg="#0f172a",
                                 activebackground="#16a34a",
                                 activeforeground="#ffffff",
                                 pady=8,
                                 bd=0,
                                 cursor="hand2")
        btn_receiver.pack(fill="x", pady=6)

        btn_sender = tk.Button(card,
                               text="🚀 Launch SENDER (Client)",
                               command=self._launch_sender,
                               font=("Segoe UI", 11, "bold"),
                               bg=self.ACCENT_BLUE,
                               fg="#0f172a",
                               activebackground="#0284c7",
                               activeforeground="#ffffff",
                               pady=8,
                               bd=0,
                               cursor="hand2")
        btn_sender.pack(fill="x", pady=6)

    def _launch_receiver(self):
        self.root.destroy()
        rec_root = tk.Tk()
        app = receiver.ReceiverGUI(rec_root)
        rec_root.mainloop()

    def _launch_sender(self):
        self.root.destroy()
        snd_root = tk.Tk()
        app = sender.SenderGUI(snd_root)
        snd_root.mainloop()

def main():
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        if mode in ["sender", "client"]:
            snd_root = tk.Tk()
            app = sender.SenderGUI(snd_root)
            snd_root.mainloop()
            return
        elif mode in ["receiver", "server"]:
            rec_root = tk.Tk()
            app = receiver.ReceiverGUI(rec_root)
            rec_root.mainloop()
            return

    root = tk.Tk()
    app = LauncherGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
