import tkinter as tk
import json
import os
import uuid
import time
import secrets
import gc
import string
import random
import sys
import re
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_FILE = "vault.dat"
LOCKOUT_FILE = "lockout.dat"
KDF_ITERATIONS = 600_000
SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32
AUTO_LOCK_SECONDS = 300
CLIPBOARD_CLEAR_SECONDS = 30


def _password_strength(pw):
    score = 0
    if len(pw) >= 8:
        score += 1
    if len(pw) >= 12:
        score += 1
    if re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw):
        score += 1
    if re.search(r"[^a-zA-Z0-9]", pw):
        score += 1
    labels = ["veoma slaba", "slaba", "srednja", "jaka", "veoma jaka"]
    return score, labels[score]


class VaultCrypto:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def encrypt(data: dict, password: str) -> bytes:
        salt = secrets.token_bytes(SALT_SIZE)
        key = VaultCrypto.derive_key(password, salt)
        nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(key)
        plaintext = json.dumps(data).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return salt + nonce + ciphertext

    @staticmethod
    def decrypt(raw: bytes, password: str) -> dict:
        salt = raw[:SALT_SIZE]
        nonce = raw[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        ciphertext = raw[SALT_SIZE + NONCE_SIZE :]
        key = VaultCrypto.derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))


class LockoutManager:
    def __init__(self, lockout_file):
        self.lockout_file = lockout_file
        self.failed_attempts = 0
        self.last_attempt_time = 0
        self._load()

    def _load(self):
        if os.path.exists(self.lockout_file):
            try:
                with open(self.lockout_file, "r") as f:
                    data = json.load(f)
                    self.failed_attempts = data.get("failed_attempts", 0)
                    self.last_attempt_time = data.get("last_attempt_time", 0)
            except Exception:
                self.failed_attempts = 0
                self.last_attempt_time = 0

    def _save(self):
        with open(self.lockout_file, "w") as f:
            json.dump(
                {"failed_attempts": self.failed_attempts,
                 "last_attempt_time": self.last_attempt_time}, f,
            )

    def get_delay(self) -> float:
        if self.failed_attempts <= 1:
            return 0
        delay = min(2 ** (self.failed_attempts - 1), 300)
        elapsed = time.time() - self.last_attempt_time
        return max(0, delay - elapsed)

    def record_failure(self):
        self.failed_attempts += 1
        self.last_attempt_time = time.time()
        self._save()

    def reset(self):
        self.failed_attempts = 0
        self.last_attempt_time = 0
        if os.path.exists(self.lockout_file):
            os.remove(self.lockout_file)


class _CanvasText:
    def __init__(self, canvas, item_id):
        self._c = canvas
        self._id = item_id

    def config(self, **kw):
        if "text" in kw:
            self._c.itemconfig(self._id, text=kw["text"])


class PasswordManagerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Litek Secure")
        self.root.geometry("920x620")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        try:
            import ctypes
            self.root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(ctypes.c_int(1)), 4)
        except Exception:
            pass

        base = os.path.dirname(os.path.abspath(__file__))
        meipass = getattr(sys, '_MEIPASS', base)

        ico_path = os.path.join(base, "icon.ico")
        if not os.path.exists(ico_path):
            ico_path = os.path.join(meipass, "icon.ico")
        if os.path.exists(ico_path):
            self.root.iconbitmap(ico_path)

        png_path = os.path.join(base, "icon.png")
        if not os.path.exists(png_path):
            png_path = os.path.join(meipass, "icon.png")
        self._icon_images = {}
        if os.path.exists(png_path):
            img = Image.open(png_path).convert("RGBA")
            for s in (16, 20, 64):
                resized = img.resize((s, s), Image.LANCZOS)
                self._icon_images[s] = ImageTk.PhotoImage(resized)

        self.master_password = None
        self.vault_data = None
        self.last_activity = time.time()
        self.clipboard_clear_job = None
        self.selected_profile_id = None

        if getattr(sys, 'frozen', False):
            self.base_dir = os.path.dirname(sys.executable)
        else:
            self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.vault_file = os.path.join(self.base_dir, VAULT_FILE)
        self.lockout_file = os.path.join(self.base_dir, LOCKOUT_FILE)
        self.lockout = LockoutManager(self.lockout_file)

        self.bg = "#101014"
        self.bg2 = "#16161c"
        self.fg = "#b0b8c8"
        self.fg_dim = "#555b6e"
        self.fg_bright = "#d4dae8"
        self.accent = "#6e8aaf"
        self.accent_hover = "#8aa4c4"
        self.surface = "#1a1a22"
        self.surface2 = "#20202a"
        self.red = "#c45c5c"
        self.green = "#5c9a6e"
        self.yellow = "#b89a4e"
        self.border = "#2a2a36"
        self.input_bg = "#13131a"
        self.selected_bg = "#252535"

        self.root.configure(bg=self.bg)

        self.root.update_idletasks()
        sx = (self.root.winfo_screenwidth() - 920) // 2
        sy = (self.root.winfo_screenheight() - 620) // 2
        self.root.geometry(f"920x620+{sx}+{sy}")

        self.root.bind_all("<Key>", self._on_activity)
        self.root.bind_all("<Button>", self._on_activity)
        self.root.bind_all("<Motion>", self._on_activity)

        self._check_vault_exists()
        self._start_auto_lock_check()
        self.root.mainloop()

    # ─── WINDOW MANAGEMENT ──────────────────────────────────

    def _on_close(self):
        self._rain_running = False
        self._secure_clear()
        self.root.destroy()

    def _on_activity(self, event=None):
        self.last_activity = time.time()

    def _start_auto_lock_check(self):
        if self.master_password and self.vault_data:
            if time.time() - self.last_activity >= AUTO_LOCK_SECONDS:
                self._lock()
                return
        self.root.after(10_000, self._start_auto_lock_check)

    def _lock(self):
        self._secure_clear()
        self._show_login()
        self._start_auto_lock_check()

    def _secure_clear(self):
        self.master_password = None
        self.vault_data = None
        self.selected_profile_id = None
        gc.collect()

    def _clear_all(self):
        self._rain_running = False
        for w in self.root.winfo_children():
            w.destroy()

    def _check_vault_exists(self):
        if os.path.exists(self.vault_file):
            self._show_login()
        else:
            self._show_setup()

    # ─── TOAST / CUSTOM DIALOGS ─────────────────────────────

    def _show_toast(self, message, duration=1800):
        t = tk.Toplevel(self.root)
        t.overrideredirect(True)
        t.attributes("-topmost", True)
        t.configure(bg=self.accent)
        inner = tk.Label(t, text=message, font=("Consolas", 9),
                         bg=self.surface2, fg=self.fg_bright, padx=16, pady=8)
        inner.pack(padx=1, pady=1)
        t.update_idletasks()
        tw = t.winfo_reqwidth()
        rx, ry = self.root.winfo_x(), self.root.winfo_y()
        rw, rh = self.root.winfo_width(), self.root.winfo_height()
        t.geometry(f"+{rx + (rw - tw) // 2}+{ry + rh - 70}")
        t.attributes("-alpha", 0.0)

        def fade_in(a=0.0):
            if a < 0.95:
                t.attributes("-alpha", a)
                t.after(20, lambda: fade_in(a + 0.12))
            else:
                t.attributes("-alpha", 0.95)
                t.after(duration, lambda: fade_out(0.95))

        def fade_out(a):
            if a > 0.05:
                t.attributes("-alpha", a)
                t.after(20, lambda: fade_out(a - 0.12))
            else:
                try:
                    t.destroy()
                except Exception:
                    pass
        fade_in()

    def _msg(self, title, message, mode="info"):
        d = _DarkMsg(self.root, self, title, message, mode)
        return d.result

    def _msg_info(self, title, message):
        self._msg(title, message, "info")

    def _msg_error(self, title, message):
        self._msg(title, message, "error")

    def _msg_yesno(self, title, message):
        return self._msg(title, message, "yesno")

    # ─── RAIN BACKGROUND ────────────────────────────────────

    def _draw_bg(self):
        canvas = tk.Canvas(self.root, bg=self.bg, highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        self._rain_canvas = canvas
        self._rain_running = True
        w, h = 920, 620
        col_w = 18
        num_cols = w // col_w
        self._rain_drops = []
        hex_chars = "0123456789abcdef"
        for i in range(num_cols):
            x = i * col_w + 3
            for _ in range(3):
                start_y = random.randint(-h, h)
                speed = random.uniform(1.2, 3.5)
                trail = random.randint(5, 14)
            self._rain_drops.append({
                "x": x, "y": float(start_y), "speed": speed, "trail": trail,
            })
        self._rain_h = h
        self._rain_hex = hex_chars
        self._animate_rain()
        return canvas

    def _animate_rain(self):
        if not self._rain_running:
            return
        c = self._rain_canvas
        try:
            c.winfo_exists()
        except Exception:
            return
        if not c.winfo_exists():
            return
        c.delete("r")
        for drop in self._rain_drops:
            drop["y"] += drop["speed"] * 4
            if drop["y"] - drop["trail"] * 16 > self._rain_h:
                drop["y"] = float(random.randint(-300, -20))
                drop["speed"] = random.uniform(1.5, 4.0)
                drop["trail"] = random.randint(4, 10)
            for t in range(drop["trail"]):
                ty = drop["y"] - t * 16
                if ty < -16 or ty > self._rain_h + 16:
                    continue
                ch = random.choice(self._rain_hex) + random.choice(self._rain_hex)
                fade = max(0.0, 1.0 - t / drop["trail"])
                g = int(18 + fade * 10)
                b = int(18 + fade * 14)
                color = f"#{g:02x}{g:02x}{b:02x}"
                c.create_text(
                    drop["x"], ty, text=ch, font=("Consolas", 7),
                    fill=color, anchor="nw", tags="r",
                )
        c.tag_lower("r")
        c.after(60, self._animate_rain)

    # ─── SHARED WIDGETS ─────────────────────────────────────

    def _entry(self, parent, show=None, width=28):
        return tk.Entry(
            parent, show=show, font=("Consolas", 11), width=width,
            bg=self.input_bg, fg=self.fg_bright, insertbackground=self.accent,
            relief="flat", highlightthickness=1, highlightcolor=self.accent,
            highlightbackground=self.border, selectbackground=self.accent,
            selectforeground=self.bg,
        )

    def _btn(self, parent, text, cmd, style="default"):
        colors = {
            "default": (self.surface2, self.fg, self.accent),
            "primary": (self.accent, self.bg, self.accent_hover),
            "danger":  (self.surface2, self.red, self.red),
            "success": (self.surface2, self.green, self.green),
            "ghost":   (self.bg, self.fg_dim, self.fg),
        }
        bg, fg, active_bg = colors.get(style, colors["default"])
        return tk.Button(
            parent, text=text, font=("Consolas", 9), bg=bg, fg=fg,
            activebackground=active_bg, activeforeground=self.bg,
            relief="flat", cursor="hand2", command=cmd, padx=10, pady=4,
            borderwidth=0,
        )

    # ─── SETUP ───────────────────────────────────────────────

    def _show_setup(self):
        self._clear_all()

        c = self._draw_bg()
        self._setup_canvas = c
        cx = 460
        y = 68

        if 64 in self._icon_images:
            c.create_image(cx, y, image=self._icon_images[64], anchor="n")
            y += 80

        c.create_text(cx, y, text="litek secure", font=("Consolas", 26, "bold"),
                       fill=self.fg_bright, anchor="n")
        y += 44
        c.create_text(cx, y, text="AES-256-GCM  /  PBKDF2-SHA256  /  lokalna enkripcija",
                       font=("Consolas", 8), fill=self.fg_dim, anchor="n")
        y += 40
        c.create_line(cx - 180, y, cx + 180, y, fill=self.border)
        y += 30
        c.create_text(cx, y, text="Nema recovery mehanizma. Zapamtite šifru.",
                       font=("Consolas", 9), fill=self.red, anchor="n")
        y += 40

        lx = cx - 175
        c.create_text(lx, y, text="master šifra", font=("Consolas", 9),
                       fill=self.fg_dim, anchor="nw")
        y += 20
        self.setup_p1 = self._entry(c, show="•", width=38)
        c.create_window(lx, y, window=self.setup_p1, anchor="nw", width=350, height=34)
        y += 38

        self._str_bg = c.create_rectangle(lx, y, lx + 350, y + 4, fill=self.surface2, outline="")
        self._str_fg = c.create_rectangle(lx, y, lx, y + 4, fill=self.green, outline="")
        y += 8
        self._str_lbl = c.create_text(lx, y, text="", font=("Consolas", 8),
                                       fill=self.fg_dim, anchor="nw")
        y += 20

        self.setup_p1.bind("<KeyRelease>", self._update_setup_strength)

        c.create_text(lx, y, text="ponovi šifru", font=("Consolas", 9),
                       fill=self.fg_dim, anchor="nw")
        y += 20
        self.setup_p2 = self._entry(c, show="•", width=38)
        c.create_window(lx, y, window=self.setup_p2, anchor="nw", width=350, height=34)
        self.setup_p2.bind("<Return>", lambda e: self._create_vault())
        y += 48

        sid = c.create_text(cx, y, text="", font=("Consolas", 9), fill=self.red, anchor="n")
        self.setup_status = _CanvasText(c, sid)
        y += 28
        btn = self._btn(c, "   inicijaliziraj   ", self._create_vault, "primary")
        c.create_window(cx, y, window=btn, anchor="n")
        self.setup_p1.focus_set()

    def _update_setup_strength(self, event=None):
        pw = self.setup_p1.get()
        c = self._setup_canvas
        lx = 460 - 175
        if not pw:
            c.coords(self._str_fg, lx, 0, lx, 0)
            c.itemconfig(self._str_lbl, text="")
            return
        score, label = _password_strength(pw)
        colors = [self.red, self.red, self.yellow, self.green, self.accent]
        fill_w = int(350 * (score + 1) / 5)
        y1 = c.coords(self._str_bg)[1]
        c.coords(self._str_fg, lx, y1, lx + fill_w, y1 + 4)
        c.itemconfig(self._str_fg, fill=colors[score])
        c.itemconfig(self._str_lbl, text=label, fill=colors[score])

    def _create_vault(self):
        p1 = self.setup_p1.get()
        p2 = self.setup_p2.get()
        if not p1:
            self.setup_status.config(text="šifra ne može biti prazna")
            return
        if len(p1) < 8:
            self.setup_status.config(text="minimalno 8 karaktera")
            return
        if p1 != p2:
            self.setup_status.config(text="šifre se ne poklapaju")
            return
        self.master_password = p1
        self.vault_data = {"version": 1, "profiles": {}}
        self._save_vault()
        self.lockout.reset()
        self.last_activity = time.time()
        self._show_main()

    # ─── LOGIN ───────────────────────────────────────────────

    def _show_login(self):
        self._clear_all()

        c = self._draw_bg()
        cx = 460
        y = 100

        if 64 in self._icon_images:
            c.create_image(cx, y, image=self._icon_images[64], anchor="n")
            y += 80

        c.create_text(cx, y, text="litek secure", font=("Consolas", 26, "bold"),
                       fill=self.fg_bright, anchor="n")
        y += 44
        c.create_text(cx, y, text="zaključano", font=("Consolas", 10),
                       fill=self.red, anchor="n")
        y += 40
        c.create_line(cx - 180, y, cx + 180, y, fill=self.border)
        y += 35

        delay = self.lockout.get_delay()
        if delay > 0:
            c.create_text(cx, y, text=f"sljedeći pokušaj za {int(delay)}s",
                           font=("Consolas", 9), fill=self.yellow, anchor="n")
            y += 28

        lx = cx - 175
        c.create_text(lx, y, text="master šifra", font=("Consolas", 9),
                       fill=self.fg_dim, anchor="nw")
        y += 20
        self.login_pass = self._entry(c, show="•", width=38)
        c.create_window(lx, y, window=self.login_pass, anchor="nw", width=350, height=34)
        self.login_pass.bind("<Return>", lambda e: self._do_login())
        y += 48

        sid = c.create_text(cx, y, text="", font=("Consolas", 9), fill=self.red, anchor="n")
        self.login_status = _CanvasText(c, sid)
        y += 28
        btn = self._btn(c, "   otključaj   ", self._do_login, "primary")
        c.create_window(cx, y, window=btn, anchor="n")
        self.login_pass.focus_set()

    def _do_login(self):
        delay = self.lockout.get_delay()
        if delay > 0:
            self.login_status.config(text=f"sačekajte {int(delay)}s")
            return
        password = self.login_pass.get()
        if not password:
            self.login_status.config(text="unesite šifru")
            return
        try:
            with open(self.vault_file, "rb") as f:
                raw = f.read()
            data = VaultCrypto.decrypt(raw, password)
        except Exception:
            self.lockout.record_failure()
            d = self.lockout.get_delay()
            msg = "pogrešna šifra"
            if d > 0:
                msg += f"  —  lockout {int(d)}s"
            self.login_status.config(text=msg)
            return
        self.master_password = password
        self.vault_data = data
        self.lockout.reset()
        self.last_activity = time.time()
        self._show_main()

    # ─── MAIN ────────────────────────────────────────────────

    def _show_main(self):
        self._clear_all()


        top = tk.Frame(self.root, bg=self.surface, height=36)
        top.pack(fill="x")
        top.pack_propagate(False)

        pc = len(self.vault_data["profiles"])
        te = sum(len(p.get("entries", {})) for p in self.vault_data["profiles"].values())
        tk.Label(
            top, text=f"  {pc} profila  /  {te} podataka  |  auto-lock: {AUTO_LOCK_SECONDS // 60}m",
            font=("Consolas", 8), bg=self.surface, fg=self.fg_dim,
        ).pack(side="left", padx=4)

        self._btn(top, "zaključaj", self._lock, "danger").pack(side="right", padx=8, pady=5)
        self._btn(top, "promijeni šifru", self._show_change_password, "ghost").pack(
            side="right", padx=2, pady=5)

        tk.Frame(self.root, bg=self.border, height=1).pack(fill="x")

        body = tk.Frame(self.root, bg=self.bg)
        body.pack(fill="both", expand=True)

        # Left sidebar
        left = tk.Frame(body, bg=self.surface, width=250)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        lbl_row = tk.Frame(left, bg=self.surface)
        lbl_row.pack(fill="x", padx=12, pady=(12, 6))
        tk.Label(lbl_row, text="profili", font=("Consolas", 9, "bold"),
                 bg=self.surface, fg=self.fg_dim).pack(side="left")

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_profiles())
        se = tk.Entry(
            left, textvariable=self.search_var, font=("Consolas", 9),
            bg=self.input_bg, fg=self.fg, insertbackground=self.accent,
            relief="flat", highlightthickness=1, highlightcolor=self.border,
            highlightbackground=self.border,
        )
        se.pack(fill="x", padx=12, pady=(0, 8), ipady=4)

        btn_row = tk.Frame(left, bg=self.surface)
        btn_row.pack(fill="x", padx=12, pady=(0, 8))
        self._btn(btn_row, "+ dodaj", self._add_profile, "success").pack(
            side="left", expand=True, fill="x", padx=(0, 3))
        self._btn(btn_row, "obriši", self._delete_profile, "danger").pack(
            side="right", expand=True, fill="x", padx=(3, 0))

        # Profile list as scrollable custom rows
        list_container = tk.Frame(left, bg=self.bg)
        list_container.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self._profile_canvas = tk.Canvas(list_container, bg=self.bg, highlightthickness=0)
        self._profile_inner = tk.Frame(self._profile_canvas, bg=self.bg)
        self._profile_inner.bind("<Configure>",
            lambda e: self._profile_canvas.configure(scrollregion=self._profile_canvas.bbox("all")))
        pcw = self._profile_canvas.create_window((0, 0), window=self._profile_inner, anchor="nw")
        self._profile_canvas.bind("<Configure>",
            lambda e: self._profile_canvas.itemconfig(pcw, width=e.width))
        self._profile_canvas.pack(fill="both", expand=True)
        self._profile_canvas.bind_all("<MouseWheel>",
            lambda e: self._profile_canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        tk.Frame(body, bg=self.border, width=1).pack(side="left", fill="y")

        self.detail = tk.Frame(body, bg=self.bg)
        self.detail.pack(side="right", fill="both", expand=True)

        self._profile_ids = []
        self._refresh_profiles()
        self._show_empty_detail()

    def _show_empty_detail(self):
        for w in self.detail.winfo_children():
            w.destroy()
        tk.Label(
            self.detail, text="izaberite profil",
            font=("Consolas", 11), bg=self.bg, fg="#222230",
        ).place(relx=0.5, rely=0.5, anchor="center")

    def _refresh_profiles(self):
        for w in self._profile_inner.winfo_children():
            w.destroy()
        self._profile_ids = []
        query = self.search_var.get().lower() if hasattr(self, "search_var") else ""
        for pid, p in sorted(
            self.vault_data["profiles"].items(), key=lambda x: x[1]["name"].lower()
        ):
            if query and query not in p["name"].lower():
                continue
            self._profile_ids.append(pid)
            n = len(p.get("entries", {}))
            selected = (pid == self.selected_profile_id)

            row = tk.Frame(self._profile_inner, bg=self.surface if selected else self.bg,
                           cursor="hand2")
            row.pack(fill="x", pady=1)

            accent_bar = tk.Frame(row, bg=self.accent if selected else self.bg, width=3)
            accent_bar.pack(side="left", fill="y")

            info = tk.Frame(row, bg=row["bg"], padx=8, pady=6)
            info.pack(side="left", fill="x", expand=True)

            tk.Label(info, text=p["name"], font=("Consolas", 10),
                     bg=row["bg"], fg=self.fg_bright if selected else self.fg).pack(
                side="left", anchor="w")
            tk.Label(info, text=str(n), font=("Consolas", 8),
                     bg=row["bg"], fg=self.fg_dim).pack(side="right")

            for widget in [row, accent_bar, info] + info.winfo_children():
                widget.bind("<Button-1>", lambda e, p=pid: self._select_profile(p))
                widget.bind("<Enter>", lambda e, r=row, ab=accent_bar, inf=info, s=selected:
                    self._profile_hover(r, ab, inf, True, s))
                widget.bind("<Leave>", lambda e, r=row, ab=accent_bar, inf=info, s=selected:
                    self._profile_hover(r, ab, inf, False, s))

    def _profile_hover(self, row, accent_bar, info, entering, selected):
        if selected:
            return
        bg = self.surface2 if entering else self.bg
        for w in [row, info]:
            w.configure(bg=bg)
        for child in info.winfo_children():
            child.configure(bg=bg)
        accent_bar.configure(bg=self.fg_dim if entering else self.bg)

    def _select_profile(self, pid):
        self.selected_profile_id = pid
        self._refresh_profiles()
        self._show_profile(pid)

    # ─── PROFILE DETAIL ─────────────────────────────────────

    def _show_profile(self, pid):
        for w in self.detail.winfo_children():
            w.destroy()

        profile = self.vault_data["profiles"].get(pid)
        if not profile:
            return

        hdr = tk.Frame(self.detail, bg=self.surface, padx=18, pady=12)
        hdr.pack(fill="x")

        tk.Label(
            hdr, text=profile["name"], font=("Consolas", 16, "bold"),
            bg=self.surface, fg=self.fg_bright,
        ).pack(side="left")

        entry_count = len(profile.get("entries", {}))
        tk.Label(
            hdr, text=f"{entry_count} podataka", font=("Consolas", 8),
            bg=self.surface, fg=self.fg_dim,
        ).pack(side="left", padx=12)

        self._btn(hdr, "preimenuj", lambda: self._rename_profile(pid), "ghost").pack(
            side="right", padx=4)

        tk.Frame(self.detail, bg=self.border, height=1).pack(fill="x")

        toolbar = tk.Frame(self.detail, bg=self.bg, pady=10)
        toolbar.pack(fill="x", padx=18)
        self._btn(toolbar, "+ dodaj podatak", lambda: self._add_entry(pid), "success").pack(
            side="left", ipady=2)
        self._btn(toolbar, "generiši šifru", self._generate_password, "default").pack(
            side="left", padx=8, ipady=2)

        container = tk.Frame(self.detail, bg=self.bg)
        container.pack(fill="both", expand=True, padx=18, pady=(0, 10))

        canvas = tk.Canvas(container, bg=self.bg, highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview,
                                  bg=self.surface, troughcolor=self.bg, width=4)
        inner = tk.Frame(canvas, bg=self.bg)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        cw = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cw, width=e.width))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        entries = profile.get("entries", {})
        if not entries:
            tk.Label(inner, text="nema podataka", font=("Consolas", 10),
                     bg=self.bg, fg="#222230").pack(pady=30)
            return

        for eid, entry in entries.items():
            self._card(inner, pid, eid, entry)

    def _card(self, parent, pid, eid, entry):
        outer = tk.Frame(parent, bg=self.border, padx=1, pady=1)
        outer.pack(fill="x", pady=3)
        card = tk.Frame(outer, bg=self.surface, padx=14, pady=10)
        card.pack(fill="x")

        row = tk.Frame(card, bg=self.surface)
        row.pack(fill="x")

        tk.Label(row, text=entry["label"], font=("Consolas", 10, "bold"),
                 bg=self.surface, fg=self.accent).pack(side="left")

        btns = tk.Frame(row, bg=self.surface)
        btns.pack(side="right")
        self._btn(btns, "copy", lambda v=entry["value"]: self._copy(v), "default").pack(
            side="left", padx=2)
        self._btn(btns, "edit", lambda: self._edit_entry(pid, eid), "ghost").pack(
            side="left", padx=2)
        self._btn(btns, "del", lambda: self._delete_entry(pid, eid), "danger").pack(
            side="left", padx=2)

        val_row = tk.Frame(card, bg=self.surface)
        val_row.pack(fill="x", pady=(6, 0))

        hidden = [True]
        n = min(len(entry["value"]), 20)
        var = tk.StringVar(value="•" * n)

        tk.Label(val_row, textvariable=var, font=("Consolas", 12),
                 bg=self.surface, fg=self.fg, anchor="w").pack(side="left", fill="x", expand=True)

        def toggle(b=[None]):
            if hidden[0]:
                var.set(entry["value"])
                b[0].config(text="sakrij", fg=self.yellow)
            else:
                var.set("•" * n)
                b[0].config(text="prikaži", fg=self.fg_dim)
            hidden[0] = not hidden[0]

        sb = self._btn(val_row, "prikaži", lambda: None, "ghost")
        sb.config(command=lambda b=sb: toggle([b]))
        sb.pack(side="right")

        def hover_in(e):
            card.configure(bg=self.surface2)
            for w in [row, btns, val_row] + row.winfo_children() + btns.winfo_children() + val_row.winfo_children():
                try:
                    w.configure(bg=self.surface2)
                except Exception:
                    pass

        def hover_out(e):
            card.configure(bg=self.surface)
            for w in [row, btns, val_row] + row.winfo_children() + btns.winfo_children() + val_row.winfo_children():
                try:
                    w.configure(bg=self.surface)
                except Exception:
                    pass

        card.bind("<Enter>", hover_in)
        card.bind("<Leave>", hover_out)

    def _copy(self, value):
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        if self.clipboard_clear_job:
            self.root.after_cancel(self.clipboard_clear_job)
        self.clipboard_clear_job = self.root.after(
            CLIPBOARD_CLEAR_SECONDS * 1000, self._clear_clipboard)
        self._show_toast(f"kopirano  —  clipboard se briše za {CLIPBOARD_CLEAR_SECONDS}s")

    def _clear_clipboard(self):
        try:
            self.root.clipboard_clear()
        except Exception:
            pass
        self.clipboard_clear_job = None

    def _generate_password(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*_+-="
        pw = "".join(secrets.choice(chars) for _ in range(20))
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        if self.clipboard_clear_job:
            self.root.after_cancel(self.clipboard_clear_job)
        self.clipboard_clear_job = self.root.after(
            CLIPBOARD_CLEAR_SECONDS * 1000, self._clear_clipboard)
        self._show_toast(f"generisana i kopirana: {pw}")

    # ─── PROFILE OPS ────────────────────────────────────────

    def _add_profile(self):
        d = _Input(self.root, "novi profil", "ime profila", self)
        if d.result:
            pid = str(uuid.uuid4())
            self.vault_data["profiles"][pid] = {"name": d.result, "entries": {}}
            self._save_vault()
            self.selected_profile_id = pid
            self._refresh_profiles()
            self._show_profile(pid)

    def _rename_profile(self, pid):
        cur = self.vault_data["profiles"][pid]["name"]
        d = _Input(self.root, "preimenuj", "novo ime", self, initial=cur)
        if d.result:
            self.vault_data["profiles"][pid]["name"] = d.result
            self._save_vault()
            self._refresh_profiles()
            self._show_profile(pid)

    def _delete_profile(self):
        if not self.selected_profile_id:
            return
        pid = self.selected_profile_id
        name = self.vault_data["profiles"][pid]["name"]
        if self._msg_yesno("brisanje", f"Obrisati '{name}' i sve podatke unutra?"):
            del self.vault_data["profiles"][pid]
            self.selected_profile_id = None
            self._save_vault()
            self._refresh_profiles()
            self._show_empty_detail()

    # ─── ENTRY OPS ──────────────────────────────────────────

    def _add_entry(self, pid):
        d = _EntryInput(self.root, "novi podatak", self)
        if d.result:
            eid = str(uuid.uuid4())
            self.vault_data["profiles"][pid]["entries"][eid] = {
                "label": d.result[0], "value": d.result[1]}
            self._save_vault()
            self._show_profile(pid)

    def _edit_entry(self, pid, eid):
        entry = self.vault_data["profiles"][pid]["entries"][eid]
        d = _EntryInput(self.root, "uredi podatak", self,
                        initial_label=entry["label"], initial_value=entry["value"])
        if d.result:
            self.vault_data["profiles"][pid]["entries"][eid] = {
                "label": d.result[0], "value": d.result[1]}
            self._save_vault()
            self._show_profile(pid)

    def _delete_entry(self, pid, eid):
        label = self.vault_data["profiles"][pid]["entries"][eid]["label"]
        if self._msg_yesno("brisanje", f"Obrisati '{label}'?"):
            del self.vault_data["profiles"][pid]["entries"][eid]
            self._save_vault()
            self._show_profile(pid)

    # ─── CHANGE PASSWORD ────────────────────────────────────

    def _show_change_password(self):
        d = _ChangePass(self.root, self)
        if d.result:
            old_pw, new_pw = d.result
            if old_pw != self.master_password:
                self._msg_error("greška", "trenutna šifra nije tačna")
                return
            self.master_password = new_pw
            self._save_vault()
            self._show_toast("master šifra promijenjena")

    # ─── PERSISTENCE ────────────────────────────────────────

    def _save_vault(self):
        encrypted = VaultCrypto.encrypt(self.vault_data, self.master_password)
        if os.path.exists(self.vault_file):
            os.chmod(self.vault_file, 0o666)
        with open(self.vault_file, "wb") as f:
            f.write(encrypted)
        os.chmod(self.vault_file, 0o444)


# ─── DIALOGS ────────────────────────────────────────────────


class _DarkDialog:
    def _setup(self, parent, app, title, w, h):
        self.result = None
        self.dlg = tk.Toplevel(parent)
        self.dlg.title(title)
        self.dlg.configure(bg=app.bg)
        self.dlg.transient(parent)
        self.dlg.grab_set()
        self.dlg.resizable(False, False)

        self.body = tk.Frame(self.dlg, bg=app.bg, padx=24, pady=16)
        self.body.pack(fill="both", expand=True)

        self.dlg.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - w) // 2
        y = parent.winfo_y() + (parent.winfo_height() - h) // 2
        self.dlg.geometry(f"{w}x{h}+{x}+{y}")

        return self.body


class _DarkMsg(_DarkDialog):
    def __init__(self, parent, app, title, message, mode="info"):
        f = self._setup(parent, app, title, 420, 170)
        color = {"info": app.accent, "error": app.red, "yesno": app.yellow}.get(mode, app.fg)

        tk.Label(f, text=message, font=("Consolas", 10), bg=app.bg, fg=color,
                 wraplength=370, justify="center").pack(pady=(8, 16))

        btn_row = tk.Frame(f, bg=app.bg)
        btn_row.pack()

        if mode == "yesno":
            app._btn(btn_row, "  da  ", lambda: self._close(True), "danger").pack(side="left", padx=4)
            app._btn(btn_row, "  ne  ", lambda: self._close(False), "default").pack(side="left", padx=4)
        else:
            app._btn(btn_row, "  ok  ", lambda: self._close(None), "primary").pack()

        self.dlg.bind("<Escape>", lambda e: self._close(False if mode == "yesno" else None))
        self.dlg.wait_window()

    def _close(self, val):
        self.result = val
        self.dlg.destroy()


class _Input(_DarkDialog):
    def __init__(self, parent, title, prompt, app, initial=""):
        f = self._setup(parent, app, title, 400, 170)

        tk.Label(f, text=prompt, font=("Consolas", 9), bg=app.bg, fg=app.fg_dim).pack(anchor="w")
        self.entry = app._entry(f, width=30)
        self.entry.pack(pady=(4, 14), ipady=5, fill="x")
        self.entry.insert(0, initial)
        self.entry.bind("<Return>", lambda e: self._ok())

        app._btn(f, "sačuvaj", self._ok, "primary").pack()
        self.entry.focus_set()
        self.dlg.wait_window()

    def _ok(self):
        v = self.entry.get().strip()
        if v:
            self.result = v
        self.dlg.destroy()


class _EntryInput(_DarkDialog):
    def __init__(self, parent, title, app, initial_label="", initial_value=""):
        f = self._setup(parent, app, title, 420, 250)

        tk.Label(f, text="naziv", font=("Consolas", 9), bg=app.bg, fg=app.fg_dim).pack(anchor="w")
        self.lbl = app._entry(f, width=30)
        self.lbl.pack(pady=(2, 10), ipady=5, fill="x")
        self.lbl.insert(0, initial_label)

        tk.Label(f, text="vrijednost", font=("Consolas", 9), bg=app.bg, fg=app.fg_dim).pack(anchor="w")
        self.val = app._entry(f, width=30)
        self.val.pack(pady=(2, 14), ipady=5, fill="x")
        self.val.insert(0, initial_value)
        self.val.bind("<Return>", lambda e: self._ok())

        app._btn(f, "sačuvaj", self._ok, "primary").pack()
        self.lbl.focus_set()
        self.dlg.wait_window()

    def _ok(self):
        l = self.lbl.get().strip()
        v = self.val.get().strip()
        if l and v:
            self.result = (l, v)
        self.dlg.destroy()


class _ChangePass(_DarkDialog):
    def __init__(self, parent, app):
        self._app = app
        f = self._setup(parent, app, "promjena šifre", 420, 370)

        tk.Label(f, text="trenutna šifra", font=("Consolas", 9), bg=app.bg, fg=app.fg_dim).pack(anchor="w")
        self.old = app._entry(f, show="•", width=30)
        self.old.pack(pady=(2, 10), ipady=5, fill="x")

        tk.Label(f, text="nova šifra", font=("Consolas", 9), bg=app.bg, fg=app.fg_dim).pack(anchor="w")
        self.new1 = app._entry(f, show="•", width=30)
        self.new1.pack(pady=(2, 4), ipady=5, fill="x")

        self._str_bar_bg = tk.Frame(f, bg=app.surface2, height=4)
        self._str_bar_bg.pack(fill="x", pady=(0, 2))
        self._str_bar_fg = tk.Frame(self._str_bar_bg, bg=app.green, height=4, width=0)
        self._str_bar_fg.place(x=0, y=0, height=4, width=0)
        self._str_label = tk.Label(f, text="", font=("Consolas", 8), bg=app.bg, fg=app.fg_dim)
        self._str_label.pack(anchor="w", pady=(0, 6))
        self.new1.bind("<KeyRelease>", self._update_strength)

        tk.Label(f, text="ponovi novu", font=("Consolas", 9), bg=app.bg, fg=app.fg_dim).pack(anchor="w")
        self.new2 = app._entry(f, show="•", width=30)
        self.new2.pack(pady=(2, 6), ipady=5, fill="x")
        self.new2.bind("<Return>", lambda e: self._ok())

        self.status = tk.Label(f, text="", font=("Consolas", 9), bg=app.bg, fg=app.red)
        self.status.pack(pady=(2, 6))

        app._btn(f, "promijeni", self._ok, "primary").pack()
        self.old.focus_set()
        self.dlg.wait_window()

    def _update_strength(self, event=None):
        pw = self.new1.get()
        if not pw:
            self._str_bar_fg.place_configure(width=0)
            self._str_label.config(text="")
            return
        score, label = _password_strength(pw)
        colors = [self._app.red, self._app.red, self._app.yellow, self._app.green, self._app.accent]
        bar_w = self._str_bar_bg.winfo_width() or 350
        fill_w = int(bar_w * (score + 1) / 5)
        self._str_bar_fg.place_configure(width=fill_w)
        self._str_bar_fg.configure(bg=colors[score])
        self._str_label.config(text=label, fg=colors[score])

    def _ok(self):
        o = self.old.get()
        n1 = self.new1.get()
        n2 = self.new2.get()
        if not o or not n1 or not n2:
            self.status.config(text="sva polja su obavezna")
            return
        if len(n1) < 8:
            self.status.config(text="minimalno 8 karaktera")
            return
        if n1 != n2:
            self.status.config(text="šifre se ne poklapaju")
            return
        self.result = (o, n1)
        self.dlg.destroy()


if __name__ == "__main__":
    PasswordManagerApp()
