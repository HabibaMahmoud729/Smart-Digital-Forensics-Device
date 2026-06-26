import tkinter as tk
from tkinter import filedialog #pick file from the browser
from unittest import result
import threading
import subprocess# عشان اومر linux
import socket #للشبكة
import math
import time
import os
import re
import smtplib#لبعت الايميل

# ── Backend modules (wifi_analysis + helpers) ──
# بيشوف الwebb.py و لو مش موجود بيطبع تحذير و يسيب البرنامج يشتغل
try:
    import webb
    _WEBB_LOADED = True
except Exception as _webb_err:
    webb = None
    _WEBB_LOADED = False
    print(f"[WARN] webb not loaded: {_webb_err}")

# بيشوف ملف ال wifi_analysis.py لو مش موجود بيطبع تحذير و يسيب البرنامج يشتغل
try:
    import wifi_analysis as _wa
    _WA_LOADED = True
except Exception as _wa_load_err:
    _wa = None
    _WA_LOADED = False
    print(f"[WARN] wifi_analysis not loaded: {_wa_load_err}")

#موديل لتتبع الip adresses و بيبني timeline للattacks 
try:
    from ip_tracking import (update_ip_timeline, mark_as_attacker,
                              append_timeline_to_report,
                              generate_full_pcap_report, ip_timeline)
    _IT_LOADED = True
except ImportError:
    try:
        from ip_tracking import (update_ip_timeline, mark_as_attacker,
                                      append_timeline_to_report,
                                      generate_full_pcap_report, ip_timeline)
        _IT_LOADED = True
    except ImportError:
        _IT_LOADED = False
        print("[WARN] ip_tracking module not found")

# موديل تحليل الهوية و حساب الrisk score (لو موجود)
try:
    from real_ip import analyze_identity, risk_score
    _RI_LOADED = True
except ImportError:
    _RI_LOADED = False
    print("[WARN] real_ip module not found")

# ── Scan threading state ──
###
_scan_stop_event = threading.Event()
_scan_threads: list = []

_osk_instance = None

def show_keyboard(event=None):
    global _osk_instance
    if _osk_instance and _osk_instance.winfo_exists():
        return
    if event:
        _osk_instance = OnScreenKeyboard(event.widget)

def hide_keyboard(event=None):
    pass   # الكيبورد بيتقفل بزرار ✕ بس

def _detect_iface(hint: str = "") -> str:
    """
    بيلاقي الـ wireless interface الحقيقي تلقائياً.
    لو hint اسم interface حقيقي يرجعه، لو اسم SSID أو فاضي يبحث تلقائي.
    """
    # لو الـ hint اسم interface ونوعه wireless — تحقق إنه موجود فعلاً
    if hint and re.match(r'^(wlan|wlp|wlx|ath|mon|eth|enp|ens)', hint):
        try:
            out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
            if hint in out:
                return hint
        except Exception:
            pass
        import os as _os
        if _os.path.exists(f"/sys/class/net/{hint}"):
            return hint

    # طريقة 1: iw dev (الأدق على Raspberry Pi)
    try:
        out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
        found = re.findall(r"Interface\s+(\S+)", out)
        if found:
            return found[0]
    except Exception:
        pass

    # طريقة 2: netifaces
    try:
        import netifaces as _nif
        for iface in _nif.interfaces():
            if re.match(r'^(wlan|wlp|wlx|ath|mon)', iface):
                return iface
    except Exception:
        pass

    # طريقة 3: /sys/class/net
    try:
        import os as _os
        for iface in _os.listdir("/sys/class/net"):
            if re.match(r'^(wlan|wlp|wlx|ath|mon)', iface):
                return iface
    except Exception:
        pass

    # مفيش interface لقيناه
    return hint if hint else None

#الthread بيصحى كل 0.4 ثانية و يشوف 
def _poll_backend(wa, last_pkt, last_alert, on_packet, on_alert, stop_event,
                  interval=0.4):
    """Thread بيراقب analysis_output / alerts_output / scan_output ويبعت الجديد للـ GUI."""
    last_scan_snapshot = [frozenset()]   # بنتتبع محتوى scan_output بالكامل

    while not stop_event.is_set():
        # ── packets ──
        cur = len(wa.analysis_output)
        if cur > last_pkt[0]:
            for entry in wa.analysis_output[last_pkt[0]:cur]:
                try: on_packet(str(entry))
                except Exception: pass
            last_pkt[0] = cur

        # ── alerts ──
        cur = len(wa.alerts_output)
        if cur > last_alert[0]:
            for entry in wa.alerts_output[last_alert[0]:cur]:
                try: on_alert(str(entry))
                except Exception: pass
            last_alert[0] = cur

        # ── open ports (scan_output is a set — نبعت snapshot كامل لما يتغير) ──
        try:
            current_scan = frozenset(wa.scan_output)
            if current_scan != last_scan_snapshot[0] and current_scan:
                # نرتّب: الـ Alerts الأول، بعدين الباقي
                insecure = sorted(p for p in current_scan if p.startswith("Alert"))
                normal   = sorted(p for p in current_scan if not p.startswith("Alert"))
                snapshot = "\n".join(insecure + normal)
                try: on_packet("[PORTS]\n" + snapshot)
                except Exception: pass
                last_scan_snapshot[0] = current_scan
        except Exception:
            pass

        time.sleep(interval)
#بعد ما الsniff يوقف .بيفرغ اي بيانات فاضلة لسه ما اتعرضتش 
def _drain_backend(wa, last_pkt, last_alert, on_packet, on_alert): 
    for entry in wa.analysis_output[last_pkt[0]:]:
        try: on_packet(str(entry))
        except Exception: pass
    for entry in wa.alerts_output[last_alert[0]:]:
        try: on_alert(str(entry))
        except Exception: pass
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from email.utils import formataddr

load_dotenv()
try:
    from PIL import Image, ImageTk, ImageDraw, ImageFilter
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[WARN] Pillow not installed — run: pip install pillow")

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    print("[WARN] fpdf2 not installed — run: pip install fpdf2")



#بيجيب الpassword من ملف الenv عشان منكتبهوش فالكود مباشر

SENDER_EMAIL    = "tuqaataha180@gmail.com"
SENDER_PASSWORD = os.getenv("EMAIL_PASS")
SENDER_NAME     = "Forenxa Security System"
SMTP_SERVER     = "smtp.gmail.com"
SMTP_PORT       = 465
#المسار اللي بيتحفظ في الPDF report علي الraspberry
REPORT_DIR = "/home/pi/Desktop/pi/reports"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


#  PDF REPORT GENERATOR

FIELD_LABELS = {
    "ip_address":      "IP Address",
    "urls_found":      "URLs Found / Open Ports",
    "alerts":          "Alerts",
    "security_status": "Security Status",
    "risk_score":      "Risk Score",
    "ssl_valid":       "SSL",
    "open_ports":      "Open Ports",
}

# بيعمل الpdf من تلات اجزاء header(اسم الجهاز بلونه)و scan Infoو results table
def generate_pdf_report(results, target, scan_mode, scenario):
    if not FPDF_AVAILABLE:
        raise RuntimeError("fpdf2 غير مثبت — شغّلي: pip install fpdf2")

    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    filepath  = os.path.join(REPORT_DIR, f"Forenxa_Report_{timestamp}.pdf")

    pdf = FPDF()
    pdf.add_page()

    # ── Header banner ───
    pdf.set_fill_color(4, 7, 26)
    pdf.rect(0, 0, 210, 28, "F")
    pdf.set_text_color(0, 229, 255)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_xy(0, 8)
    pdf.cell(210, 12, "FORENXA SECURITY REPORT", 0, 1, "C")

    pdf.set_text_color(0, 0, 0)
    pdf.set_xy(10, 36)

    # ── Scan info ───
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Scan Mode : {scan_mode}", 0, 1)
    pdf.cell(0, 8, f"Scenario  : {scenario}", 0, 1)
    pdf.cell(0, 8, f"Target    : {target or 'N/A'}", 0, 1)
    pdf.cell(0, 8, f"Date      : {time.strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.ln(4)

    # ── Results table ──
    if results:
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(0, 229, 255)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(70, 10, "Field", 1, 0, "C", True)
        pdf.cell(120, 10, "Value", 1, 1, "C", True)

        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(0, 0, 0)
        fill = False
        shown_keys = set()
        #بيطبع الحاجات المعروفة الاول (ip_address,alerts,urls_found,security_status,risk_score,ssl_valid,open_ports) و بعدين اي حاجه تانيه
        for key, label in FIELD_LABELS.items():
            if key in results and key not in shown_keys:
                pdf.set_fill_color(235, 245, 250)
                pdf.cell(70, 10, label, 1, 0, "L", fill)
                pdf.cell(120, 10, str(results.get(key, "N/A")), 1, 1, "L", fill)
                shown_keys.add(key)
                fill = not fill


        for key, value in results.items():
            if key not in shown_keys:
                pdf.set_fill_color(235, 245, 250)
                pdf.cell(70, 10, key.replace("_", " ").title(), 1, 0, "L", fill)
                pdf.cell(120, 10, str(value), 1, 1, "L", fill)
                fill = not fill
    else:
        pdf.set_font("Helvetica", "I", 12)
        pdf.cell(0, 10, "No scan results available.", 0, 1)

    # ── Footer ──
    pdf.set_auto_page_break(False)
    pdf.set_y(-20)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 10, "Generated automatically by Forenxa", 0, 0, "C")

    pdf.output(filepath)
    return filepath

#بيثبت الالوان و الfont عشان نستخدمه في كل الكود 
BG_IMAGE_PATH = "icons/HOME.png"
W, H = 800, 480

BG_DEEP   = "#04071A"
BG_CARD   = "#080E28"
BG_FIELD  = "#0A0E20"
CYAN      = "#00E5FF"
MAGENTA   = "#FF2EC4"
CYAN_DIM  = "#004A55"
WHITE     = "#FFFFFF"
GREY      = "#7788AA"
GREEN     = "#00FF88"
DARK_BG   = "#050918"

F_BTN    = ("Arial", 14, "bold")
F_BTN_SM = ("Arial", 10, "bold")
F_BODY   = ("Arial", 12)
F_SMALL  = ("Arial",  9)
F_FIELD  = ("Arial", 13)
F_TITLE  = ("Arial", 24, "bold")
F_HEAD   = ("Arial", 16, "bold")


def load_bg(w=W, h=H):
    if PIL_AVAILABLE and BG_IMAGE_PATH and os.path.exists(BG_IMAGE_PATH):
        try:
            img = Image.open(BG_IMAGE_PATH).resize((w, h), Image.LANCZOS)
            overlay = Image.new("RGBA", (w, h), (4, 7, 26, 170))
            img = img.convert("RGBA")
            img = Image.alpha_composite(img, overlay).convert("RGB")
            return img
        except Exception as e:
            print(f"[WARN] Failed to load image: {e}")

    if not PIL_AVAILABLE:
        return None

    img  = Image.new("RGB", (w, h), BG_DEEP)
    draw = ImageDraw.Draw(img)
    for y in range(h):
        r = 4  + int(10 * y / h)
        g = 7  + int(18 * y / h)
        b = 26 + int(35 * y / h)
        draw.line([(0, y), (w, y)], fill=(r, g, b))
    for i in range(-h, w + h, 55):
        draw.line([(i, 0), (i + h, h)], fill=(0, 55, 80), width=1)
    for i in range(0, w + h, 70):
        draw.line([(i, 0), (i - h, h)], fill=(55, 0, 45), width=1)
    cx, cy = w // 2, h // 2
    for radius in range(250, 30, -25):
        a   = (250 - radius) / 250
        col = (int(0 * a), int(25 * a), int(60 * a))
        draw.ellipse([cx - radius, cy - radius // 2,
                      cx + radius, cy + radius // 2], fill=col)
    img = img.filter(ImageFilter.GaussianBlur(0.6))
    return img


#  COLOR HELPERS

def lighten_color(hex_color, amount=0.45):
    hex_color = hex_color.lstrip("#")
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    r = int(r + (255 - r) * amount)
    g = int(g + (255 - g) * amount)
    b = int(b + (255 - b) * amount)
    return f"#{r:02x}{g:02x}{b:02x}"



#  COPY / PASTE SUPPORT FOR ENTRY FIELDS

def enable_copy_paste(entry):
    menu = tk.Menu(entry, tearoff=0, bg=BG_FIELD, fg=WHITE,
                    activebackground=CYAN, activeforeground=BG_DEEP, bd=0)
    menu.add_command(label="Cut",        command=lambda: entry.event_generate("<<Cut>>"))
    menu.add_command(label="Copy",       command=lambda: entry.event_generate("<<Copy>>"))
    menu.add_command(label="Paste",      command=lambda: entry.event_generate("<<Paste>>"))
    menu.add_separator()
    menu.add_command(label="Select All", command=lambda: entry.select_range(0, "end"))

    def _popup(e):
        try:
            menu.tk_popup(e.x_root, e.y_root)
        finally:
            menu.grab_release()
    entry.bind("<Button-3>", _popup) 

    _VK = {67: "<<Copy>>", 86: "<<Paste>>", 88: "<<Cut>>"}

    def _on_key(e):
        ctrl_held = bool(e.state & 0x0004)
        if not ctrl_held:
            return
        if e.keycode in _VK:
            entry.event_generate(_VK[e.keycode])
            return "break"
        if e.keycode == 65: 
            entry.select_range(0, "end")
            return "break"
        k = e.keysym.lower()
        if k == "c":
            entry.event_generate("<<Copy>>"); return "break"
        if k == "v":
            entry.event_generate("<<Paste>>"); return "break"
        if k == "x":
            entry.event_generate("<<Cut>>"); return "break"
        if k == "a":
            entry.select_range(0, "end"); return "break"

    entry.bind("<Control-KeyPress>", _on_key)
    return entry


# ── On-Screen Keyboard ──
#كيبورد افتراضي 
class OnScreenKeyboard(tk.Toplevel):
    ROWS = [
        "!@#$%^&*)(_-",
        "|;:'\",.<>/?",
        "1234567890",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]

    def __init__(self, target):
        super().__init__()
        self._target = target
        self._shift  = False
        self.attributes("-topmost", True)
        self.overrideredirect(True)
        self.configure(bg=BG_DEEP)
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{sw}x240+0+{sh - 240}")
        self._build()

    def _build(self):
        S = dict(bg=BG_FIELD, fg=WHITE, font=("Helvetica", 13, "bold"),
                 bd=0, relief="flat", padx=6, pady=8,
                 activebackground=CYAN, activeforeground=BG_DEEP)
        for row in self.ROWS:
            f = tk.Frame(self, bg=BG_DEEP)
            f.pack(pady=2)
            for ch in row:
                tk.Button(f, text=ch, width=3,
                          command=lambda c=ch: self._press(c), **S).pack(side="left", padx=2)

        bot = tk.Frame(self, bg=BG_DEEP)
        bot.pack(pady=4)
        tk.Button(bot, text="Shift", width=7,
                  command=self._toggle_shift, **S).pack(side="left", padx=2)
        tk.Button(bot, text="Bksp", width=5,
                  command=self._backspace, **S).pack(side="left", padx=2)
        tk.Button(bot, text="          SPACE          ",
                  command=lambda: self._press(" "), **S).pack(side="left", padx=2)
        tk.Button(bot, text="Close", width=8,
                  command=self.destroy,
                  bg="#c0392b", fg=WHITE,
                  font=("Helvetica", 13, "bold"),
                  bd=0, relief="flat", padx=6, pady=8).pack(side="left", padx=6)

    def _toggle_shift(self):
        self._shift = not self._shift

    def _press(self, ch):
        try:
            c = ch.upper() if self._shift else ch
            self._target.insert(self._target.index("insert"), c)
            if self._shift:
                self._shift = False
        except Exception:
            pass

    def _backspace(self):
        try:
            p = self._target.index("insert")
            if p > 0:
                self._target.delete(p - 1, p)
        except Exception:
            pass


#  -SCROLLABLE LOG BOX -
#صندوق بيعرض الpackets and alert و بtouch support
class ScrollableLog(tk.Frame):

    _SWIPE_THRESHOLD = 10   # أقل عدد بكسل عشان يُعتبر swipe مش tap
    _SWIPE_SPEED     = 0.18 # كل بكسل = كم unit scroll (كبّر الرقم = أسرع)

    def __init__(self, parent, fg=WHITE, bg=BG_CARD, font=("Consolas", 9), **kw):
        super().__init__(parent, bg=bg, **kw)

        self.text = tk.Text(
            self, fg=fg, bg=bg, font=font, wrap="word",
            bd=0, highlightthickness=0, insertbackground=fg,
            state="disabled", cursor="arrow",
        )
        self.scrollbar = tk.Scrollbar(
            self, command=self.text.yview,
            bg=bg, troughcolor=BG_DEEP, activebackground=CYAN, bd=0,
        )
        self.text.config(yscrollcommand=self.scrollbar.set)

        self.text.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # ── Mouse Wheel (Desktop / Linux) ───
        self.text.bind("<MouseWheel>", self._on_wheel_win)
        self.text.bind("<Button-4>",   lambda e: self.text.yview_scroll(-3, "units"))
        self.text.bind("<Button-5>",   lambda e: self.text.yview_scroll( 3, "units"))


        self._touch_y = None
        self.text.bind("<ButtonPress-1>",   self._touch_start)
        self.text.bind("<B1-Motion>",        self._touch_move)
        self.text.bind("<ButtonRelease-1>",  self._touch_end)

    # ── Mouse Wheel ──
    def _on_wheel_win(self, e):
        self.text.yview_scroll(int(-1 * (e.delta / 120)), "units")
        return "break"

    # ── Touch helpers ──
    def _touch_start(self, e):
        self._touch_y = e.y_root

    def _touch_move(self, e):

        if self._touch_y is None:
            return
        dy = self._touch_y - e.y_root      
        if abs(dy) < 2:
            return
        units = int(dy * self._SWIPE_SPEED)
        if units:
            self.text.yview_scroll(units, "units")
        self._touch_y = e.y_root          

    def _touch_end(self, e):
        self._touch_y = None

    # ── Content API ──
    def set_text(self, content):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("end", content)
        self.text.see("end")
        self.text.config(state="disabled")

#بيضيف سطر و لو الصندوق اتملى بيحذف الاقدم
    def append_line(self, line, max_lines=500):
        self.text.config(state="normal")
        self.text.insert("end", line.rstrip("\n") + "\n")
        num_lines = int(self.text.index("end-1c").split(".")[0])
        if num_lines > max_lines:
            self.text.delete("1.0", f"{num_lines - max_lines}.0")
        self.text.see("end")
        self.text.config(state="disabled")

    def get_text(self):
        return self.text.get("1.0", "end-1c")


def title_with_rules(parent, text, fg, bg, font, x=0, y=0, width=None,
                      anchor="center", justify="center", line_pad=4):
    container = tk.Frame(parent, bg=bg)
    container.place(x=x, y=y, width=width)
    tk.Frame(container, bg=fg, height=1).pack(fill="x")
    lbl = tk.Label(container, text=text, fg=fg, bg=bg, font=font,
                    anchor=anchor, justify=justify)
    lbl.pack(fill="x", pady=line_pad)
    tk.Frame(container, bg=fg, height=1).pack(fill="x")
    return lbl


def neon_btn(parent, text, cmd, color=CYAN, w=120, h=44, font=F_BTN):
    border_color = lighten_color(color, 0.45)
    c = tk.Canvas(parent, width=w, height=h,
                  bg=parent["bg"], highlightthickness=0, bd=0, cursor="hand2")

    def _draw(filled=False):
        c.delete("all")
        fill    = border_color if filled else color
        outline = color if filled else border_color
        fg      = BG_DEEP
        r       = 10
        for (x1, y1, x2, y2, s) in [
            (2,       2,       2+2*r,   2+2*r,   90),
            (w-2-2*r, 2,       w-2,     2+2*r,   0),
            (2,       h-2-2*r, 2+2*r,   h-2,     180),
            (w-2-2*r, h-2-2*r, w-2,     h-2,     270),
        ]:
            c.create_arc(x1, y1, x2, y2, start=s, extent=90,
                         fill=fill, outline=fill)
            c.create_arc(x1, y1, x2, y2, start=s, extent=90,
                         style="arc", outline=outline, width=2)
        c.create_rectangle(2+r, 2,   w-2-r, h-2, fill=fill, outline="")
        c.create_rectangle(2,   2+r, w-2,   h-r-2, fill=fill, outline="")
        c.create_line(2+r, 2,     w-2-r, 2,     fill=outline, width=2)
        c.create_line(2+r, h-2,   w-2-r, h-2,   fill=outline, width=2)
        c.create_line(2,   2+r,   2,     h-2-r, fill=outline, width=2)
        c.create_line(w-2, 2+r,   w-2,   h-2-r, fill=outline, width=2)
        c.create_text(w//2, h//2, text=text, fill=fg, font=font, anchor="center")

    _draw()
    c.bind("<Button-1>", lambda e: cmd())
    c.bind("<Enter>",    lambda e: _draw(True))
    c.bind("<Leave>",    lambda e: _draw(False))
    return c


#  TASKBAR BUTTON

def taskbar_btn(parent, icon, label, cmd, color=CYAN):
    bw, bh = 134, 62
    c = tk.Canvas(parent, width=bw, height=bh,
                  bg=BG_CARD, highlightthickness=1,
                  highlightbackground=color, cursor="hand2")

    def _draw(filled=False):
        c.delete("all")
        bg = color if filled else BG_CARD
        fg = BG_DEEP if filled else color
        c.configure(bg=bg)
        c.create_text(bw//2, 20, text=icon,  fill=fg, font=("Arial", 18))
        c.create_text(bw//2, 42, text=label, fill=fg, font=F_BTN_SM)

    _draw()
    c.bind("<Button-1>", lambda e: cmd())
    c.bind("<Enter>",    lambda e: _draw(True))
    c.bind("<Leave>",    lambda e: _draw(False))
    return c


class ToggleSwitch:
    def __init__(self, parent, on=True, on_color=MAGENTA, off_color=GREY,
                 on_change=None, width=60, height=28):
        self._state    = on
        self._on_color = on_color
        self._off_color= off_color
        self._cb       = on_change
        self.canvas = tk.Canvas(parent, width=width, height=height,
                                bg=BG_CARD, highlightthickness=0, cursor="hand2")
        self._w, self._h = width, height
        self.canvas.bind("<Button-1>", self._click)
        self._draw()

    def _draw(self):
        c = self.canvas
        c.delete("all")
        col = self._on_color if self._state else self._off_color
        w, h = self._w, self._h
        c.create_oval(0,    1, 28,   h-1, fill=col, outline="")
        c.create_rectangle(14, 1, w-14, h-1, fill=col, outline="")
        c.create_oval(w-28, 1, w,    h-1, fill=col, outline="")
        kx = w-26 if self._state else 2
        c.create_oval(kx, 3, kx+22, h-3, fill=WHITE, outline="")

    def _click(self, e=None):
        self._state = not self._state
        self._draw()
        if self._cb:
            self._cb(self._state)

    def get(self):
        return self._state

    def pack(self, **kw):
        self.canvas.pack(**kw)

    def place(self, **kw):
        self.canvas.place(**kw)

#الscrolling بتاع الmouse
class GlobeAnim:
    def __init__(self, canvas, cx, cy, size=44):
        self.canvas = canvas
        self.cx, self.cy, self.size = cx, cy, size
        self.angle  = 0
        self._dots  = []
        self._job   = None
        self._pts   = []
        for i in range(15):
            lat = math.radians((i / 14) * 180 - 90)
            for j in range(10):
                lon = math.radians((j / 9) * 360)
                self._pts.append((
                    math.cos(lat) * math.cos(lon),
                    math.cos(lat) * math.sin(lon),
                    math.sin(lat)
                ))

    def _color(self, br):
        return "#{:02x}{:02x}{:02x}".format(0, int(160*br), int(230*br))

    def draw(self):
        for d in self._dots:
            try: self.canvas.delete(d)
            except: pass
        self._dots = []
        cos_r = math.cos(self.angle)
        sin_r = math.sin(self.angle)
        for (x, y, z) in self._pts:
            rx = x*cos_r - y*sin_r
            ry = x*sin_r + y*cos_r
            br = (ry + 1) / 2
            if br < 0.18:
                continue
            sc = self.size / (2.5 - ry*0.3)
            px = self.cx + rx*sc
            py = self.cy - z*sc
            r  = max(1, int(br*2.5))
            dot = self.canvas.create_oval(
                px-r, py-r, px+r, py+r,
                fill=self._color(br), outline="")
            self._dots.append(dot)
        self.angle += 0.04

    def start(self):
        self._animate()

    def _animate(self):
        self.draw()
        self._job = self.canvas.after(50, self._animate)

    def stop(self):
        if self._job:
            self.canvas.after_cancel(self._job)
            self._job = None


class BaseScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=BG_DEEP)
        self.controller = controller

    def _set_bg(self):
        if self.controller._bg_photo:
            lbl = tk.Label(self, image=self.controller._bg_photo, bd=0)
            lbl.place(x=0, y=0, width=W, height=H)
            lbl.lower()
    def add_lines(self, y_pos, title_height=45):
        tk.Frame(self, bg=CYAN, height=2).place(x=40, y=y_pos + 15, width=720)
        tk.Frame(self, bg=CYAN, height=2).place(x=40, y=y_pos - title_height , width=720)

    def on_show(self):
        pass

#بيظهلر الشاشة المطلوبه لقدام
class SecurityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Security Analysis Tool")
        self.geometry(f"{W}x{H}+0+0")
        self.resizable(False, False)
        self.configure(bg=BG_DEEP)
        self.attributes("-fullscreen", True)
        self.bind("<Escape>", lambda e: self.attributes("-fullscreen", False))
        self.bind("<F11>",    lambda e: self.attributes("-fullscreen", True))

        # ── On-Screen Keyboard — شغال على كل Entry في الـ App تلقائياً ──
        self.bind_all("<FocusIn>",
                      lambda e: show_keyboard(e) if isinstance(e.widget, tk.Entry) else None)
        self.bind_all("<FocusOut>",
                      lambda e: hide_keyboard(e) if isinstance(e.widget, tk.Entry) else None)

        self.current_url            = tk.StringVar(value="")
        self.current_log_path       = tk.StringVar(value="")   # ملف اللوج المختار لسيناريو Passive
        self.current_pcap_path      = tk.StringVar(value="")   # ملف الـ PCAP لسيناريو Forensics
        self.scan_mode              = tk.StringVar(value="Web")
        self.scan_scenario          = tk.StringVar(value="Discovery")
        self.scan_results           = {}
        self.current_target_network = ""
        self._scan_cancelled        = threading.Event()
        self._scan_thread           = None

        self._bg_photo = None
        if PIL_AVAILABLE:
            pil_img = load_bg(W, H)
            if pil_img:
                self._bg_photo = ImageTk.PhotoImage(pil_img)

        container = tk.Frame(self, bg=BG_DEEP)
        container.place(x=0, y=0, width=W, height=H)

        self.frames = {}
        for Cls in (WelcomeScreen, NetworkSettingsScreen,
                    WebSettingsScreen, ScenarioScreen, WebScenarioScreen, LogPickerScreen,
                    NetworkPcapPickerScreen, ScanningScreen, ReportScreen, EmailScreen,
                    AnalysisResultScreen, PcapResultScreen,
                    HelpScreen, SettingsScreen):
            name = Cls.__name__
            f = Cls(container, self)
            self.frames[name] = f
            f.place(x=0, y=0, width=W, height=H)
        self.show_frame("WelcomeScreen")

    def show_frame(self, name):
        f = self.frames[name]
        f.tkraise()
        if hasattr(f, "on_show"):
            f.on_show()
    
    def schedule_ui(self, ms, cb):
        self.after(ms, cb)
    # لدالة دي بتستدعي webb.run_web_scan_for_gui() مباشرةً. webb.py بيعمل الـ scan وبيرجع dict من النتايج.
    def start_web_scan(self, url, on_complete, on_error):
        #بيستخدم الwebb.pyعشان يشغل الactive scan على الurl اللي المستخدم دخله
        self._scan_cancelled.clear()
        scenario = self.scan_scenario.get()

        def _worker():
            if not _WEBB_LOADED or webb is None:
                if not self._scan_cancelled.is_set():
                    self.schedule_ui(0, lambda: on_error(
                        "webb.py module not loaded.\nMake sure webb.py is in the same folder as last.py."
                    ))
                return
            try:
                results = webb.run_web_scan_for_gui(url, scenario=scenario)
            except Exception as e:
                if not self._scan_cancelled.is_set():
                    self.schedule_ui(0, lambda: on_error(str(e)))
                return

            if self._scan_cancelled.is_set():
                return

            if results.get("error"):
                self.schedule_ui(0, lambda: on_error(results["error"]))
                return

            self.scan_results = results
            self.schedule_ui(0, lambda: on_complete(results))

        self._scan_thread = threading.Thread(target=_worker, daemon=True)
        self._scan_thread.start()

    def start_log_analysis(self, log_path, on_complete, on_error):
        self._scan_cancelled.clear()
        scenario = self.scan_scenario.get()  # "Passive"

        def _worker():
            if not _WEBB_LOADED or webb is None:
                if not self._scan_cancelled.is_set():
                    self.schedule_ui(0, lambda: on_error(
                        "webb.py module not loaded.\nMake sure webb.py is in the same folder as last.py."
                    ))
                return
            analyze_fn = getattr(webb, "run_log_analysis_for_gui", None)
            if analyze_fn is None:
                if not self._scan_cancelled.is_set():
                    self.schedule_ui(
                        0,
                        lambda: on_error(
                            "run_log_analysis_for_gui not found in webb.py.\n"
                            "Add: def run_log_analysis_for_gui(log_path, scenario): ..."
                        ),
                    )
                return

            try:
                results = analyze_fn(log_path, scenario=scenario)
            except Exception as e:
                if not self._scan_cancelled.is_set():
                    self.schedule_ui(0, lambda: on_error(str(e)))
                return

            if self._scan_cancelled.is_set():
                return

            if results.get("error"):
                self.schedule_ui(0, lambda: on_error(results["error"]))
                return

            self.scan_results = results
            self.schedule_ui(0, lambda: on_complete(results))

        self._scan_thread = threading.Thread(target=_worker, daemon=True)
        self._scan_thread.start()

    #بيبعت الpackets لل wa.process_packet_live()اللي موجودة في الwifi_analysis.py
    def start_network_scan(self, target, on_complete, on_error):
        self._scan_cancelled.clear()

        screen = self.frames.get("AnalysisResultScreen")
        if screen:
            screen.alerts_data.set_text("")
            screen.packet_data.set_text("")

        def _on_alert(alert_text):
            if self._scan_cancelled.is_set():
                return
            self.schedule_ui(0, lambda a=alert_text: self._push_live_alert(a))

        def _on_packet(pkt_text):
            if self._scan_cancelled.is_set():
                return
            self.schedule_ui(0, lambda p=pkt_text: self._push_live_packet(p))

        def _on_complete_wrapper(results):
            self.scan_results = results
            self.schedule_ui(0, lambda: on_complete(results))

        def _on_error_wrapper(err):
            if self._scan_cancelled.is_set():
                return
            self.schedule_ui(0, lambda: on_error(err))

        try:
            global _scan_stop_event, _scan_threads
            _scan_stop_event = threading.Event()
            _scan_threads.clear()

            if not _WA_LOADED:
                self.schedule_ui(0, lambda: on_error("wifi_analysis module not loaded"))
                return

            wa = _wa
            real_iface = _detect_iface(target)

            # Reset backend state
            wa.analysis_output.clear()
            wa.alerts_output.clear()
            wa.scan_output.clear()
            wa.ENABLE_ACTIVE_SCAN = True   # تشغيل port scanning لايف
            wa.mode = '1'                  # live mode — لازم يتعرّف قبل الـ sniff
            wa.MONITOR_IFACE      = real_iface
            wa.MY_BSSID           = ""
            try:
                wa.build_arp_table()
            except Exception:
                pass

            last_pkt   = [0]
            last_alert = [0]

            # Poll thread
            poll_t = threading.Thread(
                target=_poll_backend,
                args=(wa, last_pkt, last_alert, _on_packet, _on_alert, _scan_stop_event),
                daemon=True,
            )
            poll_t.start()
            _scan_threads.append(poll_t)

            # Sniff thread
            def _sniff():
                try:
                    import scapy.all as scapy
                    import platform as _pl
                    sniff_kwargs = dict(
                        prn=wa.process_packet_live, store=0, promisc=True,
                        stop_filter=lambda p: _scan_stop_event.is_set(),
                    )
                    if real_iface:
                        sniff_kwargs["iface"] = real_iface
                        if _pl.system() != "Darwin":
                            sniff_kwargs["monitor"] = True
                    scapy.sniff(**sniff_kwargs)
                except Exception as e:
                    if not _scan_stop_event.is_set():
                        self.schedule_ui(0, lambda err=str(e): _on_error_wrapper(err))
                # ── Sniff ended ──
                _scan_stop_event.set()
                time.sleep(0.6)
                _drain_backend(wa, last_pkt, last_alert, _on_packet, _on_alert)
                try:
                    wa.flush_port_scan_reports(); wa.flush_dos_reports()
                    wa.flush_udp_ddos_reports(); wa.flush_icmp_ddos_reports()
                    wa.flush_syn_ddos_reports(); wa.flush_botnet_reports()
                    wa.flush_deauth_reports()
                except Exception:
                    pass
                _on_complete_wrapper({
                    "alerts":   list(wa.alerts_output),
                    "analysis": list(wa.analysis_output),
                    "scan":     list(wa.scan_output),
                })

            sniff_t = threading.Thread(target=_sniff, daemon=True)
            sniff_t.start()
            _scan_threads.append(sniff_t)
        except Exception as e:
            self.schedule_ui(0, lambda: on_error(str(e)))

    def _push_live_alert(self, alert_text):
        """بيعرض الـ alert مباشرةً في ScanningScreen وهي شغالة"""
        scan_screen = self.frames.get("ScanningScreen")
        if scan_screen:
            scan_screen.push_alert(alert_text.strip())
        # كمان نحدّث AnalysisResultScreen لو اتفتحت بعدين
        ar_screen = self.frames.get("AnalysisResultScreen")
        if ar_screen:
            ar_screen.alerts_data.append_line(alert_text.strip())

    def _push_live_packet(self, pkt_text):
        """بيعرض الـ packet مباشرةً في ScanningScreen وهي شغالة"""
        scan_screen = self.frames.get("ScanningScreen")
        ar_screen   = self.frames.get("AnalysisResultScreen")

        if pkt_text.startswith("[PORTS]\n"):
            ports_content = pkt_text[len("[PORTS]\n"):]
            if scan_screen:
                scan_screen.push_port(ports_content.strip())
            if ar_screen:
                ar_screen.ports_data.set_text(ports_content)
        else:
            if scan_screen:
                scan_screen.push_packet(pkt_text.strip())
            if ar_screen:
                ar_screen.packet_data.append_line(pkt_text.strip())

    # ── PCAP / Forensics Mode ──
    #بيحلل PCAP File عن طريق wa.analyze_pcap()
    def start_pcap_analysis(self, path, on_complete, on_error):
        """ بيحلل PCAP file مباشرةً من wifi_analysis."""
        self._scan_cancelled.clear()

        screen = self.frames.get("PcapResultScreen")
        if screen:
            screen.pcap_data.set_text("")
            screen.forensics_alerts.set_text("")

        def _on_alert(alert_text):
            if self._scan_cancelled.is_set():
                return
            self.schedule_ui(0, lambda a=alert_text: self._push_pcap_alert(a))

        def _on_packet(pkt_text):
            if self._scan_cancelled.is_set():
                return
            self.schedule_ui(0, lambda p=pkt_text: self._push_pcap_packet(p))

        def _on_complete_wrapper(results):
            self.scan_results = results
            self.schedule_ui(0, lambda: on_complete(results))

        def _on_error_wrapper(err):
            if self._scan_cancelled.is_set():
                return
            self.schedule_ui(0, lambda: on_error(err))

        try:
            global _scan_stop_event, _scan_threads
            _scan_stop_event = threading.Event()
            _scan_threads.clear()

            if not _WA_LOADED:
                self.schedule_ui(0, lambda: on_error("wifi_analysis module not loaded"))
                return

            wa = _wa
            wa.analysis_output.clear()
            wa.alerts_output.clear()
            wa.scan_output.clear()
            wa.ENABLE_ACTIVE_SCAN = False
            wa.mode = '2'    # PCAP mode

            last_pkt   = [0]
            last_alert = [0]

            # Poll thread
            poll_t = threading.Thread(
                target=_poll_backend,
                args=(wa, last_pkt, last_alert, _on_packet, _on_alert, _scan_stop_event),
                daemon=True,
            )
            poll_t.start()
            _scan_threads.append(poll_t)

            # PCAP analysis thread
            def _run_pcap():
                try:
                    wa.analyze_pcap(path)
                except Exception as e:
                    _scan_stop_event.set()
                    self.schedule_ui(0, lambda err=str(e): _on_error_wrapper(err))
                    return
                try:
                    wa.flush_port_scan_reports(); wa.flush_dos_reports()
                    wa.flush_udp_ddos_reports(); wa.flush_icmp_ddos_reports()
                    wa.flush_syn_ddos_reports(); wa.flush_botnet_reports()
                    wa.flush_deauth_reports()
                except Exception:
                    pass
                _scan_stop_event.set()
                time.sleep(0.6)
                _drain_backend(wa, last_pkt, last_alert, _on_packet, _on_alert)
                _on_complete_wrapper({
                    "alerts":   list(wa.alerts_output),
                    "analysis": list(wa.analysis_output),
                    "scan":     list(wa.scan_output),
                })

            pcap_t = threading.Thread(target=_run_pcap, daemon=True)
            pcap_t.start()
            _scan_threads.append(pcap_t)
        except Exception as e:
            self.schedule_ui(0, lambda: on_error(str(e)))

    def _push_pcap_alert(self, alert_text):
        screen = self.frames.get("PcapResultScreen")
        if screen:
            screen.forensics_alerts.append_line(alert_text.strip())

    def _push_pcap_packet(self, pkt_text):
        screen = self.frames.get("PcapResultScreen")
        if screen:
            screen.pcap_data.append_line(pkt_text.strip())

    def stop_web_scan(self):
        """بيوقف الـ web scan أو الـ live sniffing"""
        self._scan_cancelled.set()
        if self.scan_mode.get() == "Network":
            _scan_stop_event.set()

    def connect_to_wifi(self, ssid, password):

        import platform as _platform
        system = _platform.system()

        try:
            if system == "Windows":
                # على ويندوز لازم بروفايل الشبكة يتعمل الأول بالباسورد، بعدين نتصل بيه
                profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig><SSID><name>{ssid}</name></SSID></SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM><security>
        <authEncryption>
            <authentication>WPA2PSK</authentication>
            <encryption>AES</encryption>
            <useOneX>false</useOneX>
        </authEncryption>
        <sharedKey>
            <keyType>passPhrase</keyType>
            <protected>false</protected>
            <keyMaterial>{password}</keyMaterial>
        </sharedKey>
    </security></MSM>
</WLANProfile>"""
                tmp_path = os.path.join(os.environ.get("TEMP", "."), f"{ssid}_profile.xml")
                with open(tmp_path, "w") as f:
                    f.write(profile_xml)
                subprocess.run(
                    f'netsh wlan add profile filename="{tmp_path}"',
                    shell=True, capture_output=True, text=True
                )
                result = subprocess.run(
                    f'netsh wlan connect name="{ssid}" ssid="{ssid}"',
                    shell=True, capture_output=True, text=True
                )
                time.sleep(3)  
                check = subprocess.run(
                    "netsh wlan show interfaces",
                    shell=True, capture_output=True, text=True
                )
                if ssid in check.stdout and "connected" in check.stdout.lower():
                    return True, ""
                return False, "Wrong password or unable to connect."

            else:
                # Linux / Raspberry Pi — نجرب nmcli الأول
                try:
                    result = subprocess.run(
                        ["nmcli", "dev", "wifi", "connect", ssid, "password", password],
                        capture_output=True, text=True, timeout=30
                    )
                    output = (result.stdout + result.stderr).lower()
                    print(f"[nmcli] rc={result.returncode} out={output[:300]}")

                    # نجح لو returncode=0 أو لو في الـ output كلمة connected/activated
                    success_keywords = ["successfully activated", "device", "connected",
                                        "activation complete", "connection successfully"]
                    if result.returncode == 0 or any(k in output for k in success_keywords):
                        # تأكد إنه اتصل فعلاً
                        time.sleep(3)
                        verify = subprocess.run(
                            ["nmcli", "-t", "-f", "GENERAL.STATE,GENERAL.CONNECTION", "dev", "show"],
                            capture_output=True, text=True, timeout=10
                        )
                        v_out = verify.stdout.lower()
                        print(f"[nmcli verify] {v_out[:200]}")
                        if "connected" in v_out or ssid.lower() in v_out:
                            return True, ""

                    # فشل — نعرف السبب
                    if any(k in output for k in ["secrets were required",
                                                  "802-11-wireless-security.psk",
                                                  "key-mgmt", "invalid password",
                                                  "wrong password"]):
                        return False, "Wrong password."
                    if "no network with ssid" in output:
                        return False, f"Network '{ssid}' not found."

                except FileNotFoundError:
                    pass  # nmcli مش موجود — نجرب wpa_supplicant

                # Fallback: wpa_supplicant (لو nmcli مش موجود أو فشل)
                try:
                    iface = _detect_iface("")
                    if not iface:
                        return False, "No wireless interface found."

                    wpa_conf = (
                        f'network={{\n'
                        f'    ssid="{ssid}"\n'
                        f'    psk="{password}"\n'
                        f'    key_mgmt=WPA-PSK\n'
                        f'}}\n'
                    )
                    conf_path = "/tmp/_wpa_tmp.conf"
                    with open(conf_path, "w") as _f:
                        _f.write(wpa_conf)

                    subprocess.run(["wpa_cli", "-i", iface, "reconfigure"],
                                   capture_output=True, timeout=5)
                    subprocess.run(["wpa_supplicant", "-B", "-i", iface,
                                    "-c", conf_path],
                                   capture_output=True, timeout=10)
                    time.sleep(5)
                    dhcp = subprocess.run(["dhclient", iface],
                                          capture_output=True, timeout=15)
                    # تحقق من الاتصال
                    # نجرب نجيب IP بأكتر من طريقة
                    for dhcp_cmd in [
                        ["dhclient", "-v", iface],
                        ["dhcpcd", iface],
                        ["udhcpc", "-i", iface],
                    ]:
                        try:
                            subprocess.run(dhcp_cmd, capture_output=True, timeout=15)
                            time.sleep(3)
                            chk = subprocess.run(["ip", "route"],
                                                 capture_output=True, text=True)
                            if "default" in chk.stdout:
                                return True, ""
                        except (FileNotFoundError, subprocess.TimeoutExpired):
                            continue

                    # تحقق أخير — ممكن الـ IP اتأخر شوية
                    time.sleep(4)
                    chk = subprocess.run(["ip", "addr", "show", iface],
                                         capture_output=True, text=True)
                    if "inet " in chk.stdout:
                        return True, ""

                    return False, "Connected but failed to get IP. Try: sudo dhclient " + iface
                except Exception as e2:
                    return False, f"Failed: {e2}"

                return False, "Wrong password or failed to connect."

        except subprocess.TimeoutExpired:
            return False, "Connection timed out."
        except FileNotFoundError:
            return False, "nmcli not found on this system."
        except Exception as e:
            return False, str(e)

    def send_report_email(self, email, results, url):
        try:
            pdf_path = generate_pdf_report(
                results,
                url or self.current_target_network,
                self.scan_mode.get(),
                self.scan_scenario.get(),
            )

            msg = MIMEMultipart()
            msg["From"]    = formataddr((SENDER_NAME, SENDER_EMAIL))
            msg["To"]      = email
            msg["Subject"] = "Forenxa Security Scan Report"

            body = (
                "Hi,\n\n"
                "Attached is the Forenxa security scan report.\n\n"
                f"Scan Mode : {self.scan_mode.get()}\n"
                f"Scenario  : {self.scan_scenario.get()}\n"
                f"Target    : {url or self.current_target_network or 'N/A'}\n"
                f"Date      : {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                "Regards,\nForenxa"
            )
            msg.attach(MIMEText(body, "plain"))

            with open(pdf_path, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={os.path.basename(pdf_path)}",
            )
            msg.attach(part)

            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.sendmail(SENDER_EMAIL, email, msg.as_string())

            return True, pdf_path

        except Exception as e:
            return False, str(e)



#  SCREEN 1 — WELCOME

class WelcomeScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._globe = None
        self._build()

    def _build(self):
        self._set_bg()
        tk.Label(self, text="WELCOME In FORENXA", fg=CYAN, bg=BG_DEEP, font=F_TITLE).place(x=0, y=22, width=W)
        self.add_lines(50, title_height=40)

        outer = tk.Frame(self, bg=BG_CARD, highlightbackground=CYAN_DIM, highlightthickness=1)
        outer.place(x=30, y=74, width=740, height=285)

        net = tk.Frame(outer, bg=BG_CARD, highlightbackground=CYAN, highlightthickness=2, cursor="hand2")
        net.place(x=12, y=12, width=340, height=261)

        self._gc = tk.Canvas(net, width=100, height=100, bg=BG_CARD, highlightthickness=0)
        self._gc.pack(pady=(20, 6))

        tk.Label(net, text="Network", fg=CYAN, bg=BG_CARD, font=("Arial", 20, "bold")).pack()
        tk.Label(net, text="MODE", fg=GREY, bg=BG_CARD, font=("Arial", 10)).pack()
        tk.Label(net, text="Scan networks & open ports", fg=GREY, bg=BG_CARD, font=F_SMALL).pack(pady=(4, 0))

        for w in [net] + list(net.winfo_children()):
            w.bind("<Button-1>", lambda e: self._go("Network"))

        def _net_enter(e): net.config(highlightbackground=WHITE)
        def _net_leave(e): net.config(highlightbackground=CYAN)
        for w in [net] + list(net.winfo_children()):
            w.bind("<Enter>", _net_enter)
            w.bind("<Leave>", _net_leave)

        web = tk.Frame(outer, bg=BG_CARD, highlightbackground=MAGENTA, highlightthickness=2, cursor="hand2")
        web.place(x=388, y=12, width=340, height=261)

        wc = tk.Canvas(web, width=100, height=100, bg=BG_CARD, highlightthickness=0)
        wc.pack(pady=(20, 6))
        self._draw_www(wc, 50, 50, 42)

        tk.Label(web, text="Web", fg=MAGENTA, bg=BG_CARD, font=("Arial", 22, "bold")).pack()
        tk.Label(web, text="MODE", fg=GREY, bg=BG_CARD, font=("Arial", 10)).pack()
        tk.Label(web, text="Analyse URLs & web security", fg=GREY, bg=BG_CARD, font=F_SMALL).pack(pady=(4, 0))

        for w in [web] + list(web.winfo_children()):
            w.bind("<Button-1>", lambda e: self._go("Web"))

        def _web_enter(e): web.config(highlightbackground=WHITE)
        def _web_leave(e): web.config(highlightbackground=MAGENTA)
        for w in [web] + list(web.winfo_children()):
            w.bind("<Enter>", _web_enter)
            w.bind("<Leave>", _web_leave)

        tb = tk.Frame(self, bg=BG_CARD, highlightbackground=MAGENTA, highlightthickness=1)
        tb.place(x=30, y=370, width=740, height=74)

        taskbar_items = [
            ("⏻",  "Shutdown",  self._shutdown,  MAGENTA),
            ("↺",  "Restart",   self._restart,   CYAN),
            ("🔍", "Detection", self._detection, CYAN),
            ("?",  "Help",      self._help,      CYAN),
            ("⚙",  "Settings",  self._settings,  CYAN),
        ]
        for icon, label, cmd, col in taskbar_items:
            taskbar_btn(tb, icon, label, cmd, col).pack(side="left", expand=True, fill="both", padx=2, pady=4)

    def on_show(self):
        if self._globe:
            self._globe.stop()
        self._globe = GlobeAnim(self._gc, 50, 50)
        self._globe.start()

    def _go(self, mode):
        if self._globe:
            self._globe.stop()
        self.controller.scan_mode.set(mode)
        if mode == "Network":
            self.controller.show_frame("NetworkSettingsScreen")
        else:
            self.controller.show_frame("WebScenarioScreen")

    def _draw_www(self, c, cx, cy, s):
        c.create_rectangle(cx-s, cy-s*.75, cx+s, cy+s*.5, outline=MAGENTA, width=2, fill="")
        for i, x in enumerate([cx-s*.55, cx-s*.30, cx-s*.05]):
            c.create_oval(x, cy-s*.72, x+6, cy-s*.60, fill=MAGENTA if i == 0 else GREY, outline="")
        c.create_text(cx-s*.1, cy-s*.12, text="WWW", fill=MAGENTA, font=("Arial", int(s*.35), "bold"))
        ax, ay = cx+s*.2, cy+s*.18
        c.create_line(ax, ay, ax+s*.3, ay+s*.28, fill=MAGENTA, width=2)
        c.create_line(ax, ay, ax+s*.08, ay+s*.32, fill=MAGENTA, width=2)
        c.create_line(cx-s*.28, cy+s*.5,  cx+s*.28, cy+s*.5,  fill=MAGENTA, width=2)
        c.create_line(cx,       cy+s*.5,  cx,        cy+s*.72, fill=MAGENTA, width=2)
        c.create_line(cx-s*.28, cy+s*.72, cx+s*.28, cy+s*.72, fill=MAGENTA, width=2)

    def _shutdown(self): self.controller.destroy()
    def _restart(self): self.controller.destroy()
    def _detection(self):
        self.controller.scan_mode.set("Web")
        self.controller.show_frame("WebScenarioScreen")
    def _help(self):     self.controller.show_frame("HelpScreen")
    def _settings(self): self.controller.show_frame("SettingsScreen")



#  SCREEN 2 — NETWORK SETTINGS 


class NetworkSettingsScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._target_var = tk.StringVar(value="")
        self._active_pwd_frame = None
        self._build()

    def _build(self):
        self._set_bg()

        tk.Label(self, text="Network Settings", fg=CYAN, bg=BG_DEEP, font=F_TITLE).place(x=0, y=18, width=W)
        self.add_lines(60)
        # الكارت الرئيسي للشبكات
        card = tk.Frame(self, bg=BG_CARD, highlightbackground=CYAN, highlightthickness=1)
        card.place(x=30, y=62, width=740, height=290)

        hdr = tk.Frame(card, bg=BG_CARD)
        hdr.pack(fill="x", padx=20, pady=(16, 10))
        tk.Frame(card, bg=CYAN, height=1).pack(fill="x", padx=20, before=hdr)

        tk.Label(hdr, text="Available Networks", fg=CYAN, bg=BG_CARD, font=F_HEAD).pack(side="left")
        #مفتاح تشغيل و ايقاف مرسوم
        self._sw = ToggleSwitch(hdr, on=False, on_color=CYAN, off_color=GREY, on_change=self._toggle_wifi)
        self._sw.canvas.pack(side="right")

        tk.Frame(card, bg=CYAN_DIM, height=1).pack(fill="x", padx=20)

        list_container = tk.Frame(card, bg=BG_CARD)
        list_container.pack(fill="both", expand=True, padx=20, pady=10)

        self._canvas = tk.Canvas(list_container, bg=BG_CARD, highlightthickness=0, bd=0)
        self._vsb = tk.Scrollbar(list_container, orient="vertical",
                                  command=self._canvas.yview,
                                  bg=BG_CARD, troughcolor=BG_DEEP,
                                  activebackground=CYAN, bd=0, relief="flat", width=8)
        self._canvas.configure(yscrollcommand=self._vsb.set)
        self._vsb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self.list_area = tk.Frame(self._canvas, bg=BG_CARD)
        self._list_win = self._canvas.create_window((0, 0), window=self.list_area, anchor="nw")

        self._canvas.bind("<Configure>",
            lambda e: self._canvas.itemconfig(self._list_win, width=e.width))
        self.list_area.bind("<Configure>",
            lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))

        for _w in (self._canvas, self.list_area):
            _w.bind("<MouseWheel>",
                    lambda e: self._canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
            _w.bind("<Button-4>", lambda e: self._canvas.yview_scroll(-1, "units"))
            _w.bind("<Button-5>", lambda e: self._canvas.yview_scroll(1, "units"))

        tk.Label(self.list_area, text="Enable WiFi toggle to scan networks",
                 fg=GREY, bg=BG_CARD, font=F_SMALL).pack(pady=15)

        self._val = tk.Label(self, text="", fg=MAGENTA, bg=BG_DEEP, font=F_SMALL)
        self._val.place(x=30, y=362, width=740)

        neon_btn(self, "Back", lambda: self.controller.show_frame("WelcomeScreen"), color=MAGENTA, w=120, h=44).place(x=30, y=416)
        neon_btn(self, "Start Scan", self._proceed, color=CYAN, w=150, h=44).place(x=620, y=416)

    def on_show(self):
        self._val.config(text="")
        self._active_pwd_frame = None
        self._target_var.set("")

    def _toggle_wifi(self, state):
        for w in self.list_area.winfo_children():
            w.destroy()
        self._active_pwd_frame = None

        if not state:
            tk.Label(self.list_area, text="WiFi is Disabled", fg=GREY, bg=BG_CARD, font=F_SMALL).pack(pady=15)
            return

        loading = tk.Label(self.list_area, text="Scanning...", fg=CYAN, bg=BG_CARD, font=F_BODY)
        loading.pack(pady=12)
        self.update()

        nets = self._scan_wifi_real()
        loading.destroy()

        if not nets:
            tk.Label(self.list_area, text="No networks found", fg=MAGENTA, bg=BG_CARD, font=F_SMALL).pack(pady=12)
            return
        for name, pwr in nets:
            self._net_card(name, pwr)

    def _scan_wifi_real(self):
        import platform
        system = platform.system()
        nets = []
        seen = set()

        if system == "Windows":
            try:
                raw = subprocess.check_output(
                    "netsh wlan show networks mode=bssid",
                    shell=True, stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="ignore")
                ssid, signal = None, "N/A"
                for line in raw.splitlines():
                    line = line.strip()
                    if line.startswith("SSID") and "BSSID" not in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            ssid = parts[1].strip()
                    elif "Signal" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            signal = parts[1].strip().replace("%", "")
                        if ssid and ssid not in seen:
                            nets.append((ssid, signal))
                            seen.add(ssid)
                        ssid, signal = None, "N/A"
            except Exception:
                pass
        else:
            # أولاً نجرّب nmcli (Kali / Bookworm مع NetworkManager)
            try:
                raw = subprocess.check_output(
                    "nmcli -t -f SSID,SIGNAL dev wifi list",
                    shell=True, stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="ignore")
                for line in raw.strip().splitlines():
                    if ":" in line:
                        ssid, sig = line.rsplit(":", 1)
                        ssid = ssid.strip()
                        sig  = sig.strip()
                        if ssid and ssid not in seen:
                            nets.append((ssid, sig))
                            seen.add(ssid)
            except Exception:
                pass
            # fallback: iw scan (لو nmcli مش موجود)
            if not nets:
                try:
                    iface_out = subprocess.check_output(
                        ["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
                    iface_m = __import__("re").search(r"Interface\s+(\S+)", iface_out)
                    iface = iface_m.group(1) if iface_m else "wlan0"
                    raw = subprocess.check_output(
                        ["sudo", "iw", "dev", iface, "scan"],
                        text=True, stderr=subprocess.DEVNULL, timeout=15)
                    ssid, sig = None, "N/A"
                    for line in raw.splitlines():
                        line = line.strip()
                        if line.startswith("SSID:"):
                            ssid = line.split(":", 1)[1].strip()
                        elif line.lower().startswith("signal:"):
                            try:
                                dbm = float(line.split(":")[1].strip().split()[0])
                                sig = str(max(0, min(100, int(2 * (dbm + 100)))))
                            except Exception:
                                sig = "N/A"
                        if ssid and ssid not in seen:
                            nets.append((ssid, sig))
                            seen.add(ssid)
                            ssid, sig = None, "N/A"
                except Exception:
                    pass

        return nets

    def _net_card(self, name, signal):
        card = tk.Frame(self.list_area, bg=BG_CARD, highlightbackground=CYAN_DIM, highlightthickness=1)
        card.pack(fill="x", pady=4, padx=2)
        
        top = tk.Frame(card, bg=BG_CARD, cursor="hand2")
        top.pack(fill="x", side="top", padx=12, pady=6)
        
        lbl_icon = tk.Label(top, text="📶", fg=CYAN, bg=BG_CARD, font=("Arial", 12))
        lbl_icon.pack(side="left", padx=(0, 8))
        
        inf = tk.Frame(top, bg=BG_CARD)
        inf.pack(side="left", fill="y")
        lbl_name = tk.Label(inf, text=name, fg=WHITE, bg=BG_CARD, font=("Arial", 12, "bold"), anchor="w")
        lbl_name.pack(fill="x")
        lbl_sig = tk.Label(inf, text=f"Signal: {signal}%", fg=GREY, bg=BG_CARD, font=F_SMALL, anchor="w")
        lbl_sig.pack(fill="x")
        
        # جزء الباسورد المخفي
        pwd_frame = tk.Frame(card, bg=BG_CARD)
        
        def toggle_expand(event=None):
            if self._active_pwd_frame and self._active_pwd_frame != pwd_frame:
                self._active_pwd_frame.pack_forget()
            
            if pwd_frame.winfo_manager():
                pwd_frame.pack_forget()
                self._active_pwd_frame = None
            else:
                pwd_frame.pack(fill="x", padx=12, pady=(2, 10))
                self._active_pwd_frame = pwd_frame
                self._target_var.set(name)
                self.controller.current_target_network = name

        for widget in (top, lbl_icon, inf, lbl_name, lbl_sig):
            widget.bind("<Button-1>", toggle_expand)

        def _bind_scroll(w):
            w.bind("<MouseWheel>",
                   lambda e: self._canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
            w.bind("<Button-4>", lambda e: self._canvas.yview_scroll(-1, "units"))
            w.bind("<Button-5>", lambda e: self._canvas.yview_scroll(1, "units"))
            for child in w.winfo_children():
                _bind_scroll(child)
        self.after(50, lambda: _bind_scroll(card))
        tk.Label(pwd_frame, text="Password:", fg=GREY, bg=BG_CARD, font=F_BODY).pack(side="left", padx=(4, 8))
        
        pe_f = tk.Frame(pwd_frame, bg=BG_FIELD, highlightbackground=CYAN_DIM, highlightthickness=1)
        pe_f.pack(side="left", fill="x", expand=True, padx=4)
        
        pwd_var = tk.StringVar()
        pe = tk.Entry(pe_f, textvariable=pwd_var, show="*", font=F_FIELD, fg=CYAN, bg=BG_FIELD, bd=0, insertbackground=CYAN)
        pe.pack(fill="x", padx=8, pady=5)
        
        connecting = {"busy": False}

        def handle_connect():
            if connecting["busy"]:
                return
            password = pwd_var.get().strip()
            if not password:
                self._val.config(text="⚠  Please enter the network password.", fg=MAGENTA)
                return

            connecting["busy"] = True
            self._val.config(text=f"⏳  Connecting to {name}...", fg=CYAN)

            def _worker():
                ok, msg = self.controller.connect_to_wifi(name, password)
                def _update():
                    connecting["busy"] = False
                    if ok:
                        self._val.config(text=f"✔  Connected to {name} successfully!", fg=GREEN)
                    else:
                        self._val.config(text=f"✖  {msg}", fg=MAGENTA)
                self.controller.schedule_ui(0, _update)

            threading.Thread(target=_worker, daemon=True).start()

        neon_btn(pwd_frame, "Connect", handle_connect, color=MAGENTA, w=85, h=30, font=F_BTN_SM).pack(side="right", padx=(8, 4))

    def _proceed(self):
        target = self._target_var.get().strip()
        if not target:
            self._val.config(text="⚠  Please tap on a network and enter its password first.", fg=MAGENTA)
            return
        self._val.config(text="")
        self.controller.current_url.set(target)
        self.controller.show_frame("ScenarioScreen")



#  SCREEN 2 — WEB SETTINGS


class WebSettingsScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._selected = 0
        self._build()

    def _build(self):
        self._set_bg()
        card = tk.Frame(self, bg=BG_CARD, highlightbackground=CYAN, highlightthickness=2)
        card.place(x=30, y=30, width=740, height=384)

        hdr = tk.Frame(card, bg=BG_CARD)
        hdr.pack(fill="x", padx=20, pady=(16, 8))
        tk.Frame(card, bg=CYAN, height=1).pack(fill="x", padx=20, before=hdr)
        tk.Label(hdr, text="Web Settings", fg=CYAN, bg=BG_CARD, font=F_HEAD).pack(side="left")
        
        self._toggle = ToggleSwitch(hdr, on=True, on_color=MAGENTA, off_color=GREY)
        self._toggle.canvas.pack(side="right")

        tk.Frame(card, bg=CYAN, height=1).pack(fill="x", padx=20, pady=2)

        ef = tk.Frame(card, bg=BG_FIELD, highlightbackground=CYAN, highlightthickness=1)
        ef.pack(fill="x", padx=20, pady=(12, 4))
        self._url_entry = tk.Entry(ef, textvariable=self.controller.current_url, font=F_FIELD, fg=CYAN, bg=BG_FIELD, insertbackground=CYAN, relief="flat", bd=0)
        self._url_entry.pack(fill="x", padx=12, pady=10)
        enable_copy_paste(self._url_entry)
        self._set_ph()
        self._url_entry.bind("<FocusIn>",  self._clear_ph)
        self._url_entry.bind("<FocusOut>", self._set_ph)

        pr = tk.Frame(card, bg=BG_CARD)
        pr.pack(fill="x", padx=20, pady=(4, 6))
        for p in ["https://", "http://", "ftp://"]:
            neon_btn(pr, p, lambda x=p: self._insert_proto(x), color=CYAN, w=85, h=32, font=F_BTN_SM).pack(side="left", padx=4)

        tk.Frame(card, bg=CYAN, height=1).pack(fill="x", padx=20, pady=4)

        self._list_frame = tk.Frame(card, bg=BG_CARD)
        self._list_frame.pack(fill="both", expand=True, padx=20, pady=(4, 8))
        self._items = [
            ("Target Website", "e.g. https://example.com"),
            ("IP / Domain",    "Auto-resolved"),
            ("Scan Depth",     "Standard"),
            ("Other...",       ""),
        ]
        self._draw_list()

        self._val = tk.Label(self, text="", fg=MAGENTA, bg=BG_DEEP, font=F_SMALL)
        self._val.place(x=30, y=424, width=740)

        neon_btn(self, "Back", lambda: self.controller.show_frame("WebScenarioScreen"), color=MAGENTA, w=120, h=44).place(x=30, y=432)
        neon_btn(self, "Next", self._proceed, color=MAGENTA, w=120, h=44).place(x=650, y=432)

    def _draw_list(self):
        for w in self._list_frame.winfo_children(): w.destroy()
        for i, (name, val) in enumerate(self._items):
            bg = BG_FIELD if i == self._selected else BG_CARD
            row = tk.Frame(self._list_frame, bg=bg, cursor="hand2")
            row.pack(fill="x", pady=1)
            tk.Label(row, text=name, fg=WHITE, bg=bg, font=F_BODY, anchor="w", width=22).pack(side="left", padx=10, pady=6)
            tk.Label(row, text=val, fg=GREY, bg=bg, font=F_BODY, anchor="e").pack(side="right", padx=10)
            tk.Frame(self._list_frame, bg=CYAN_DIM, height=1).pack(fill="x")
            for w in [row] + list(row.winfo_children()):
                w.bind("<Button-1>", lambda e, i=i: self._sel(i))

    def _sel(self, i):
        self._selected = i
        self._draw_list()

    def _set_ph(self, e=None):
        if not self.controller.current_url.get():
            self._url_entry.insert(0, "https://example.com")
            self._url_entry.config(fg=GREY)

    def _clear_ph(self, e=None):
        if self._url_entry.get() == "https://example.com":
            self._url_entry.delete(0, "end")
            self._url_entry.config(fg=CYAN)

    def _insert_proto(self, p):
        cur = self.controller.current_url.get()
        if cur in ("", "https://example.com"):
            self.controller.current_url.set(p)
            self._url_entry.config(fg=CYAN)
        self._url_entry.icursor("end")
        self._url_entry.focus_set()

    def _proceed(self):
        url = self.controller.current_url.get().strip()
        if not url or url == "https://example.com":
            self._val.config(text="⚠  Please enter a URL first.")
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            self._val.config(text="⚠  URL must start with http:// or https://")
            return
        self._val.config(text="")
        self.controller.scan_scenario.set("Active")
        self.controller.show_frame("ScanningScreen")

    def on_show(self): self._val.config(text="")



#  SCREEN 3a — CHOOSE SCENARIO (NETWORK MODE)
#  بتظهر بس لما scan_mode == "Network" — Live Mode (Discovery) أو Forensics Mode (Incident Response)

class ScenarioScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "NETWORK FORENSICS & INTRUSION \n DETECTION SYSTEM", CYAN, BG_DEEP, F_TITLE, x=0, y=18, width=W)

        d = tk.Frame(self, bg=BG_CARD, highlightbackground=CYAN, highlightthickness=2, cursor="hand2")
        d.place(x=30, y=130, width=356, height=250)

        rc = tk.Canvas(d, width=100, height=100, bg=BG_CARD, highlightthickness=0)
        rc.pack(pady=(22, 8))
        self._draw_radar(rc, 50, 50, 42)

        tk.Label(d, text="Live Mode", fg=CYAN, bg=BG_CARD, font=("Arial", 16, "bold")).pack()
        tk.Label(d, text="Discover networks & system info", fg=GREY, bg=BG_CARD, font=F_SMALL, wraplength=300).pack(pady=(4, 0))

        for w in [d] + list(d.winfo_children()): w.bind("<Button-1>", lambda e: self._go("Discovery"))
        def _de(e): d.config(highlightbackground=WHITE)
        def _dl(e): d.config(highlightbackground=CYAN)
        for w in [d] + list(d.winfo_children()):
            w.bind("<Enter>", _de); w.bind("<Leave>", _dl)

        ir = tk.Frame(self, bg=BG_CARD, highlightbackground=MAGENTA, highlightthickness=2, cursor="hand2")
        ir.place(x=414, y=130, width=356, height=250)

        wc = tk.Canvas(ir, width=100, height=100, bg=BG_CARD, highlightthickness=0)
        wc.pack(pady=(22, 8))
        self._draw_warning(wc, 50, 50, 42)

        tk.Label(ir, text="Forensics\nMode", fg=MAGENTA, bg=BG_CARD, font=("Arial", 16, "bold"), justify="center").pack()
        tk.Label(ir, text="Handle security incidents", fg=GREY, bg=BG_CARD, font=F_SMALL).pack(pady=(4, 0))

        for w in [ir] + list(ir.winfo_children()): w.bind("<Button-1>", lambda e: self._go("Incident Response"))
        def _ie(e): ir.config(highlightbackground=WHITE)
        def _il(e): ir.config(highlightbackground=MAGENTA)
        for w in [ir] + list(ir.winfo_children()):
            w.bind("<Enter>", _ie); w.bind("<Leave>", _il)

        neon_btn(self, "Back", self._go_back, color=MAGENTA, w=120, h=44).place(x=W//2 - 60, y=404)

    def _draw_radar(self, c, cx, cy, s):
        for r in [s, int(s*.68), int(s*.36)]:
            c.create_oval(cx-r, cy-r, cx+r, cy+r, outline=CYAN, width=1, fill="")
        ax, ay = cx - int(s*.28), cy + int(s*.28)
        c.create_line(cx, cy, ax, ay, fill=CYAN, width=3)
        c.create_polygon(ax, ay, ax+12, ay-4, ax+4, ay+12, fill=CYAN)

    def _draw_warning(self, c, cx, cy, s):
        pts = [cx, cy-s, cx+s*.9, cy+s*.7, cx-s*.9, cy+s*.7]
        c.create_polygon(pts, outline=MAGENTA, fill="", width=3)
        c.create_text(cx, cy+int(s*.18), text="!", fill=MAGENTA, font=("Arial", int(s*.7), "bold"))

    def _go(self, scenario):
        self.controller.scan_scenario.set(scenario)
        if scenario == "Incident Response":
            # Forensics Mode: المستخدم يختار ملف PCAP الأول
            self.controller.show_frame("NetworkPcapPickerScreen")
        else:
            # Discovery Mode: يروح مباشرة للـ Scanning (Live sniffing)
            self.controller.show_frame("ScanningScreen")

    def _go_back(self):
        self.controller.show_frame("NetworkSettingsScreen")

class WebScenarioScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "WEB SECURITY ANALYSIS \n CHOOSE SCAN TYPE", MAGENTA, BG_DEEP, F_TITLE, x=0, y=18, width=W)

        # ── Analyze Logs (Passive) ──
        logs = tk.Frame(self, bg=BG_CARD, highlightbackground=CYAN, highlightthickness=2, cursor="hand2")
        logs.place(x=30, y=130, width=356, height=250)

        lc = tk.Canvas(logs, width=100, height=100, bg=BG_CARD, highlightthickness=0)
        lc.pack(pady=(22, 8))
        self._draw_log_icon(lc, 50, 50, 42)

        tk.Label(logs, text="Analyze Logs", fg=CYAN, bg=BG_CARD, font=("Arial", 16, "bold")).pack()
        tk.Label(logs, text="(Passive - analyze a log file)", fg=GREY, bg=BG_CARD,
                 font=F_SMALL, wraplength=300).pack(pady=(4, 0))

        for w in [logs] + list(logs.winfo_children()):
            w.bind("<Button-1>", lambda e: self._pick_log_and_go())
        def _le(e): logs.config(highlightbackground=WHITE)
        def _ll(e): logs.config(highlightbackground=CYAN)
        for w in [logs] + list(logs.winfo_children()):
            w.bind("<Enter>", _le); w.bind("<Leave>", _ll)

        # ── Scan URL (Active) ──
        url_card = tk.Frame(self, bg=BG_CARD, highlightbackground=MAGENTA, highlightthickness=2, cursor="hand2")
        url_card.place(x=414, y=130, width=356, height=250)

        uc = tk.Canvas(url_card, width=100, height=100, bg=BG_CARD, highlightthickness=0)
        uc.pack(pady=(22, 8))
        self._draw_target_icon(uc, 50, 50, 42)

        tk.Label(url_card, text="Scan URL", fg=MAGENTA, bg=BG_CARD, font=("Arial", 16, "bold")).pack()
        tk.Label(url_card, text="(Active - scan for vulnerabilities)", fg=GREY, bg=BG_CARD,
                 font=F_SMALL, wraplength=300).pack(pady=(4, 0))

        for w in [url_card] + list(url_card.winfo_children()):
            w.bind("<Button-1>", lambda e: self._go_active())
        def _ue(e): url_card.config(highlightbackground=WHITE)
        def _ul(e): url_card.config(highlightbackground=MAGENTA)
        for w in [url_card] + list(url_card.winfo_children()):
            w.bind("<Enter>", _ue); w.bind("<Leave>", _ul)

        self._status = tk.Label(self, text="", fg=MAGENTA, bg=BG_DEEP, font=F_SMALL)
        self._status.place(x=30, y=388, width=740)

        neon_btn(self, "Back", self._go_back, color=MAGENTA, w=120, h=44).place(x=W//2 - 60, y=404)

    # ---ICONS---
    def _draw_log_icon(self, c, cx, cy, s):
        """ورقة/ملف لوج فيها خطوط بتمثل سطور الـ log"""
        x1, y1 = cx - s*.55, cy - s*.7
        x2, y2 = cx + s*.55, cy + s*.7
        fold = s*.28
        c.create_polygon(x1, y1, x2-fold, y1, x2, y1+fold, x2, y2, x1, y2,
                          outline=CYAN, fill="", width=2)
        c.create_line(x2-fold, y1, x2-fold, y1+fold, fill=CYAN, width=2)
        c.create_line(x2-fold, y1+fold, x2, y1+fold, fill=CYAN, width=2)
        for i, ly in enumerate([y1 + s*.55, y1 + s*.85, y1 + s*1.15]):
            width_ratio = 0.7 if i != 1 else 0.45
            c.create_line(x1 + s*.18, ly, x1 + s*.18 + (x2 - x1 - s*.36) * width_ratio, ly,
                           fill=CYAN, width=2)

    def _draw_target_icon(self, c, cx, cy, s):
        for r in [s, int(s*.62), int(s*.26)]:
            c.create_oval(cx-r, cy-r, cx+r, cy+r, outline=MAGENTA, width=2, fill="")
        c.create_line(cx, cy-s-6, cx, cy-s+10, fill=MAGENTA, width=2)
        c.create_line(cx, cy+s-10, cx, cy+s+6, fill=MAGENTA, width=2)
        c.create_line(cx-s-6, cy, cx-s+10, cy, fill=MAGENTA, width=2)
        c.create_line(cx+s-10, cy, cx+s+6, cy, fill=MAGENTA, width=2)
        c.create_oval(cx-4, cy-4, cx+4, cy+4, fill=MAGENTA, outline="")

    def _pick_log_and_go(self):
        """سيناريو Passive: روح لشاشة اختيار ملف اللوج وزرار Start Analysis."""
        self.controller.scan_scenario.set("Passive")
        self.controller.show_frame("LogPickerScreen")

    def _go_active(self):
        """سيناريو Active: روح لشاشة إدخال الـ URL."""
        self.controller.scan_scenario.set("Active")
        self.controller.show_frame("WebSettingsScreen")

    def _go_back(self):
        self.controller.show_frame("WelcomeScreen")

    def on_show(self):
        self._status.config(text="")



#  SCREEN 3c — PICK LOG FILE (WEB MODE / Passive scenario)
#  بتظهر لما يدوس على كارت "Analyze Logs" في WebScenarioScreen.
#  المستخدم بيختار الملف بزرار Browse، وبعدين يدوس Start Analysis عشان يكمل.

class LogPickerScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "ANALYZE LOG FILE \n (PASSIVE SCAN)", CYAN, BG_DEEP, F_TITLE, x=0, y=18, width=W)

        card = tk.Frame(self, bg=BG_CARD, highlightbackground=CYAN, highlightthickness=2)
        card.place(x=30, y=120, width=740, height=240)

        title_with_rules(card, "Log File", CYAN, BG_CARD, F_HEAD, x=20, y=14, width=700, anchor="w", justify="left")

        ef = tk.Frame(card, bg=BG_FIELD, highlightbackground=CYAN, highlightthickness=1)
        ef.pack(fill="x", padx=20, pady=(70, 4))
        self._path_lbl = tk.Label(ef, text="No file selected.", fg=GREY, bg=BG_FIELD,
                                   font=F_FIELD, anchor="w")
        self._path_lbl.pack(fill="x", padx=12, pady=10)

        neon_btn(card, "Browse...", self._browse, color=MAGENTA, w=160, h=40).pack(padx=20, pady=(14, 6), anchor="w")

        self._status = tk.Label(self, text="", fg=MAGENTA, bg=BG_DEEP, font=F_SMALL)
        self._status.place(x=30, y=372, width=740)

        neon_btn(self, "Back", self._go_back, color=MAGENTA, w=120, h=44).place(x=30, y=432)
        neon_btn(self, "Start Analysis", self._start, color=CYAN, w=180, h=44).place(x=590, y=432)

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select a log file to analyze",
            filetypes=[("Log files", "*.log *.txt *.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        self.controller.current_log_path.set(path)
        self._path_lbl.config(text=path, fg=CYAN)
        self._status.config(text="")

    def _start(self):
        path = self.controller.current_log_path.get().strip()
        if not path:
            self._status.config(text="⚠  Please choose a log file first.")
            return
        self.controller.scan_scenario.set("Passive")
        self._status.config(text="")
        self.controller.show_frame("ScanningScreen")

    def _go_back(self):
        self.controller.show_frame("WebScenarioScreen")

    def on_show(self):
        self._status.config(text="")
        path = self.controller.current_log_path.get().strip()
        if path:
            self._path_lbl.config(text=path, fg=CYAN)
        else:
            self._path_lbl.config(text="No file selected.", fg=GREY)



#  SCREEN 3d — PICK PCAP FILE (NETWORK MODE / Forensics scenario)
#  بتظهر لما يدوس على "Forensics Mode" في ScenarioScreen.
#  المستخدم يختار ملف .pcap / .pcapng وبعدين يدوس Start Analysis.

class NetworkPcapPickerScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "FORENSICS MODE\nSelect PCAP File", MAGENTA, BG_DEEP,
                          F_TITLE, x=0, y=18, width=W)

        card = tk.Frame(self, bg=BG_CARD, highlightbackground=MAGENTA, highlightthickness=2)
        card.place(x=30, y=120, width=740, height=240)

        title_with_rules(card, "PCAP / Network Capture File", MAGENTA, BG_CARD,
                          F_HEAD, x=20, y=14, width=700, anchor="w", justify="left")

        ef = tk.Frame(card, bg=BG_FIELD, highlightbackground=MAGENTA, highlightthickness=1)
        ef.pack(fill="x", padx=20, pady=(70, 4))
        self._path_lbl = tk.Label(ef, text="No file selected.", fg=GREY, bg=BG_FIELD,
                                   font=F_FIELD, anchor="w")
        self._path_lbl.pack(fill="x", padx=12, pady=10)

        neon_btn(card, "Browse...", self._browse, color=MAGENTA, w=160, h=40).pack(
            padx=20, pady=(14, 6), anchor="w")

        self._status = tk.Label(self, text="", fg=MAGENTA, bg=BG_DEEP, font=F_SMALL)
        self._status.place(x=30, y=372, width=740)

        neon_btn(self, "Back", self._go_back, color=CYAN, w=120, h=44).place(x=30, y=432)
        neon_btn(self, "Start Analysis", self._start, color=MAGENTA, w=180, h=44).place(
            x=590, y=432)

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select a PCAP file",
            filetypes=[
                ("PCAP files", "*.pcap *.pcapng *.cap *.dump"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        self.controller.current_pcap_path.set(path)
        self._path_lbl.config(text=path, fg=CYAN)
        self._status.config(text="")

    def _start(self):
        path = self.controller.current_pcap_path.get().strip()
        if not path:
            self._status.config(text="⚠  Please choose a PCAP file first.")
            return
        if not path.endswith((".pcap", ".pcapng", ".cap", ".dump", ".pcap.gz")):
            self._status.config(text="⚠  Invalid file type. Choose a .pcap or .pcapng file.")
            return
        self._status.config(text="")
        self.controller.show_frame("ScanningScreen")

    def _go_back(self):
        self.controller.show_frame("ScenarioScreen")

    def on_show(self):
        self._status.config(text="")
        path = self.controller.current_pcap_path.get().strip()
        if path:
            self._path_lbl.config(text=path, fg=CYAN)
        else:
            self._path_lbl.config(text="No file selected.", fg=GREY)



#  SCREEN 4 — SCANNING

class ScanningScreen(BaseScreen):
    """
    شاشة الـ Live Analysis:
    - بتعرض الباكيتات والأليرتس وهي بتيجي في الوقت الفعلي
    - زرار Stop لما يتضغط يظهر زرارين: Home و Next
    - لو Network mode: الداتا بتتعرض هنا مباشرةً (مش في AnalysisResultScreen)
    """
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._anim_job  = None
        self._dots      = 0
        self._back_to   = "WebSettingsScreen"
        self._next_screen = "AnalysisResultScreen"
        self._last_results = {}
        self._build()

    def _build(self):
        self._set_bg()

        # ── Header ───────────────────────────────────────────────────────────
        self._title = tk.Label(self, text="Analyzing data ...",
                               fg=CYAN, bg=BG_DEEP, font=("Arial", 18, "bold"))
        self._title.place(x=0, y=6, width=W)

        self._tgt = tk.Label(self, text="", fg=GREY, bg=BG_DEEP, font=F_SMALL)
        self._tgt.place(x=0, y=34, width=W)

        # ── Live Packets (يسار) ───────────────────────────────────────────────
        frame_left = tk.Frame(self, bg=BG_CARD,
                              highlightbackground=CYAN, highlightthickness=2)
        frame_left.place(x=10, y=55, width=490, height=310)
        tk.Label(frame_left, text="PACKET ANALYSIS (LIVE)",
                 fg=CYAN, bg=BG_CARD,
                 font=("Arial", 9, "bold")).pack(anchor="nw", padx=8, pady=4)
        self.live_packets = ScrollableLog(frame_left, fg=WHITE, bg=BG_CARD,
                                          font=("Consolas", 8))
        self.live_packets.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        # ── Live Alerts (يمين) ────────────────────────────────────────────────
        frame_right = tk.Frame(self, bg=BG_CARD,
                               highlightbackground=MAGENTA, highlightthickness=2)
        frame_right.place(x=508, y=55, width=272, height=310)
        tk.Label(frame_right, text="ALERTS",
                 fg=MAGENTA, bg=BG_CARD,
                 font=("Arial", 9, "bold")).pack(anchor="nw", padx=8, pady=4)
        self.live_alerts = ScrollableLog(frame_right, fg=WHITE, bg=BG_CARD,
                                          font=("Consolas", 8))
        self.live_alerts.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        # ── Ports bar (أسفل) ─────────────────────────────────────────────────
        frame_ports = tk.Frame(self, bg=BG_CARD,
                               highlightbackground=CYAN, highlightthickness=1)
        frame_ports.place(x=10, y=372, width=770, height=44)
        tk.Label(frame_ports, text="OPEN PORTS SCANNING",
                 fg=CYAN, bg=BG_CARD,
                 font=("Arial", 8, "bold")).pack(anchor="nw", padx=8, pady=2)
        self.live_ports = ScrollableLog(frame_ports, fg=CYAN, bg=BG_CARD,
                                         font=("Consolas", 7))
        self.live_ports.pack(fill="both", expand=True, padx=6, pady=(0, 2))

        # ── أزرار ────────────────────────────────────────────────────────────
        self._stop_btn = neon_btn(self, "Stop", self._stop,
                                  color=MAGENTA, w=130, h=40)
        self._stop_btn.place(x=W//2 - 65, y=422)

        # زرارين بيظهروا بعد Stop
        self._home_btn = neon_btn(self, "Home",
                                  lambda: self.controller.show_frame("WelcomeScreen"),
                                  color=CYAN, w=150, h=40)
        self._next_btn = neon_btn(self, "Next ▶",
                                  self._go_next,
                                  color=GREEN, w=150, h=40)

    def on_show(self):
        mode     = self.controller.scan_mode.get()
        scenario = self.controller.scan_scenario.get()
        self._back_to = "ScenarioScreen" if mode == "Network" else "WebScenarioScreen"

        # مسح الداتا القديمة
        self.live_packets.set_text("")
        self.live_alerts.set_text("")
        self.live_ports.set_text("")

        # إظهار زرار Stop وإخفاء الزرارين
        self._stop_btn.place(x=W//2 - 65, y=422)
        self._home_btn.place_forget()
        self._next_btn.place_forget()

        self._last_results = {}
        self._dots = 0

        is_passive_log = (mode == "Web" and scenario == "Passive")
        target_display = (self.controller.current_log_path.get()
                          if is_passive_log else self.controller.current_url.get())
        self._tgt.config(text=f"Target: {target_display}")
        self._title.config(text="Analyzing data ...", fg=CYAN)
        self._start_anim()

        if mode == "Network":
            self._next_screen = ("PcapResultScreen"
                                 if scenario == "Incident Response"
                                 else "AnalysisResultScreen")
            if scenario == "Incident Response":
                self.controller.start_pcap_analysis(
                    path=self.controller.current_pcap_path.get(),
                    on_complete=self._done, on_error=self._error)
            else:
                self.controller.start_network_scan(
                    target=self.controller.current_url.get(),
                    on_complete=self._done, on_error=self._error)
        elif is_passive_log:
            self._next_screen = "ReportScreen"
            self.controller.start_log_analysis(
                log_path=self.controller.current_log_path.get(),
                on_complete=self._done, on_error=self._error)
        else:
            self._next_screen = "ReportScreen"
            self.controller.start_web_scan(
                url=self.controller.current_url.get(),
                on_complete=self._done, on_error=self._error)

    # ── Live feed: بيتنادوا من controller._push_live_* ──────────────────────
    def push_packet(self, text: str):
        """بيضيف باكيت حي في الوقت الفعلي"""
        self.live_packets.append_line(text)

    def push_alert(self, text: str):
        """بيضيف أليرت حي في الوقت الفعلي"""
        self.live_alerts.append_line(text)

    def push_port(self, text: str):
        """بيضيف بورت مفتوح حي"""
        self.live_ports.append_line(text)

    # ── Animation ────────────────────────────────────────────────────────────
    def _start_anim(self):
        self._stop_anim()
        self._animate()

    def _animate(self):
        d = "." * (self._dots % 4)
        self._title.config(text=f"Analyzing data {d}")
        self._dots += 1
        self._anim_job = self.after(380, self._animate)

    def _stop_anim(self):
        if self._anim_job:
            self.after_cancel(self._anim_job)
            self._anim_job = None

    # ── Callbacks ────────────────────────────────────────────────────────────
    def _done(self, results):
        self._stop_anim()
        self._last_results = results or {}
        self._title.config(text="✔  Scan Complete!", fg=GREEN)

        mode     = self.controller.scan_mode.get()
        scenario = self.controller.scan_scenario.get()

        if mode == "Network" and scenario == "Incident Response":
            # PCAP: نملّي PcapResultScreen ثم ReportScreen
            pcap_screen   = self.controller.frames["PcapResultScreen"]
            alerts_list   = results.get("alerts",   [])
            analysis_list = results.get("analysis", [])
            scan_list     = results.get("scan",     [])
            pcap_screen.populate({
                "file":    self.controller.current_url.get(),
                "count":   str(len(analysis_list)),
                "alerts":  "\n".join(str(a)[:60] for a in alerts_list[:5]) or "No alerts",
                "summary": f"{len(alerts_list)} alerts  |  {len(scan_list)} open ports",
            })
            self._next_screen = "PcapResultScreen"

        elif mode == "Network" and scenario == "Discovery":
            # Live Network: نبني report من نتايج الـ scan الحية
            alerts_list   = results.get("alerts",   [])
            scan_list     = results.get("scan",     [])
            open_ports    = len(scan_list)
            risk          = min(len(alerts_list) * 10, 100)
            status        = ("CRITICAL" if risk >= 70 else
                             "HIGH RISK" if risk >= 40 else
                             "MEDIUM RISK" if risk >= 20 else
                             "LOW RISK" if alerts_list else "Secure")
            report_data = {
                "ip_address":      self.controller.current_url.get(),
                "urls_found":      f"{open_ports} open ports detected",
                "alerts":          f"{len(alerts_list)} alert(s)" if alerts_list else "None",
                "security_status": status,
                "risk_score":      str(risk),
                "ssl_valid":       "Check port 443",
                "open_ports":      str(open_ports),
            }
            self.controller.frames["ReportScreen"].populate(report_data)
            self._next_screen = "ReportScreen"

        else:
            # Web mode
            self.controller.frames["ReportScreen"].populate(results)
            self._next_screen = "ReportScreen"

        # إظهار زرارَي Home و Next
        self._stop_btn.place_forget()
        self._home_btn.place(x=W//2 - 165, y=422)
        self._next_btn.place(x=W//2 + 15,  y=422)

    def _error(self, err):
        self._stop_anim()
        self._title.config(text="✖  Error", fg=MAGENTA)
        self._tgt.config(text=err[:120], fg=MAGENTA)
        self._stop_btn.place_forget()
        self._home_btn.place(x=W//2 - 165, y=422)
        # لا نعرض Next لو كان فيه error

    def _stop(self):
        """لما المستخدم يضغط Stop: نوقف الـ scan ونعرض Home + Next"""
        self.controller.stop_web_scan()
        self._stop_anim()
        self._title.config(text="⏹  Stopped", fg=MAGENTA)

        # نبني الـ Report من الداتا اللي اتجمعت لحد دلوقتي
        mode     = self.controller.scan_mode.get()
        scenario = self.controller.scan_scenario.get()
        if mode == "Network" and scenario == "Discovery":
            alerts_live = self.live_alerts.get_text().strip().splitlines()
            ports_live  = [l for l in self.live_ports.get_text().strip().splitlines() if l]
            risk        = min(len(alerts_live) * 10, 100)
            status      = ("CRITICAL" if risk >= 70 else
                           "HIGH RISK" if risk >= 40 else
                           "MEDIUM RISK" if risk >= 20 else
                           "LOW RISK" if alerts_live else "Secure")
            report_data = {
                "ip_address":      self.controller.current_url.get(),
                "urls_found":      f"{len(ports_live)} open ports",
                "alerts":          f"{len(alerts_live)} alert(s)" if alerts_live else "None",
                "security_status": status,
                "risk_score":      str(risk),
                "ssl_valid":       "Check port 443",
                "open_ports":      str(len(ports_live)),
            }
            self.controller.frames["ReportScreen"].populate(report_data)
            self._next_screen = "ReportScreen"

        self._stop_btn.place_forget()
        self._home_btn.place(x=W//2 - 165, y=422)
        self._next_btn.place(x=W//2 + 15,  y=422)

    def _go_next(self):
        """زرار Next: ينقل للشاشة المناسبة"""
        self.controller.show_frame(self._next_screen)


#  SCREEN 5 — REPORT

class ReportScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._vars = {}
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "Report", CYAN, BG_DEEP, ("Arial", 22, "bold"), x=40, y=14, width=300, anchor="w", justify="left")

        self._url_lbl = tk.Label(self, text="", fg=GREY, bg=BG_DEEP, font=F_SMALL, anchor="e")
        self._url_lbl.place(x=320, y=22, width=440)

        card = tk.Frame(self, bg="#0D0D1E", highlightbackground=CYAN, highlightthickness=1)
        card.place(x=40, y=52, width=720, height=200)

        rows = [
            ("URLs Found",      "urls_found",      CYAN),
            ("Alerts",          "alerts",          CYAN),
            ("Security Status", "security_status", CYAN),
        ]
        for i, (lbl, key, col) in enumerate(rows):
            bg = "#0C0C1C" if i % 2 == 0 else "#0F0F22"
            row = tk.Frame(card, bg=bg)
            row.pack(fill="x")
            tk.Label(row, text=lbl, fg=WHITE, bg=bg, font=("Arial", 13), anchor="w", width=24).pack(side="left", padx=20, pady=14)
            var = tk.StringVar(value="—")
            self._vars[key] = var
            tk.Label(row, textvariable=var, fg=col, bg=bg, font=("Arial", 13, "bold"), anchor="e").pack(side="right", padx=20)
            if i < len(rows) - 1: tk.Frame(card, bg="#1A1A35", height=1).pack(fill="x")

        card2 = tk.Frame(self, bg="#0D0D1E", highlightbackground=CYAN_DIM, highlightthickness=1)
        card2.place(x=40, y=260, width=720, height=70)
        for lbl, key in [("IP Address","ip_address"), ("Risk Score","risk_score"), ("SSL", "ssl_valid")]:
            col2 = tk.Frame(card2, bg="#0D0D1E")
            col2.pack(side="left", expand=True, fill="both", padx=12, pady=8)
            tk.Label(col2, text=lbl, fg=GREY, bg="#0D0D1E", font=F_SMALL).pack()
            var = tk.StringVar(value="—")
            self._vars[key] = var
            tk.Label(col2, textvariable=var, fg=CYAN, bg="#0D0D1E", font=("Arial", 10, "bold")).pack()

        tk.Label(self, text="To view the full report click  Send Report", fg=CYAN, bg=BG_DEEP, font=("Arial", 9)).place(x=0, y=338, width=W)

        neon_btn(self, "Home", lambda: self.controller.show_frame("WelcomeScreen"), color=MAGENTA, w=130, h=44).place(x=40, y=416)
        neon_btn(self, "Send Report", lambda: self.controller.show_frame("EmailScreen"), color=MAGENTA, w=160, h=44).place(x=600, y=416)

    def populate(self, results):
        self._url_lbl.config(text=f"{self.controller.current_url.get()}  |  {time.strftime('%Y-%m-%d %H:%M')}")
        for key, var in self._vars.items(): var.set(results.get(key, "N/A"))
#report for each Scenario
class AnalysisResultScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "Analysis & Scanning Network", CYAN, BG_DEEP,
                         ("Arial", 16, "bold"), x=0, y=10, width=W,
                         anchor="center", justify="center")

        # ── 1. Packet Analysis — لايف (يسار) ──
        frame_left = tk.Frame(self, bg=BG_CARD,
                              highlightbackground=CYAN, highlightthickness=2)
        frame_left.place(x=20, y=50, width=490, height=305)
        tk.Label(frame_left, text="PACKET ANALYSIS(LIVE)", fg=CYAN, bg=BG_CARD,
                 font=("Arial", 10, "bold")).pack(anchor="nw", padx=10, pady=6)
        self.packet_data = ScrollableLog(frame_left, fg=WHITE, bg=BG_CARD,
                                         font=("Consolas", 8))
        self.packet_data.pack(fill="both", expand=True, padx=6, pady=(0, 8))

        # ── 2. Alerts (يمين) ──
        frame_right = tk.Frame(self, bg=BG_CARD,
                               highlightbackground=MAGENTA, highlightthickness=2)
        frame_right.place(x=525, y=50, width=255, height=305)
        tk.Label(frame_right, text="ALERTS", fg=MAGENTA, bg=BG_CARD,
                 font=("Arial", 10, "bold")).pack(anchor="nw", padx=10, pady=6)
        self.alerts_data = ScrollableLog(frame_right, fg=WHITE, bg=BG_CARD,
                                          font=("Consolas", 8))
        self.alerts_data.pack(fill="both", expand=True, padx=6, pady=(0, 8))

        # ── 3. Open Ports Scanning (أسفل يسار) ──
        frame_bottom = tk.Frame(self, bg=BG_CARD,
                                highlightbackground=CYAN, highlightthickness=2)
        frame_bottom.place(x=20, y=364, width=600, height=58)
        tk.Label(frame_bottom, text="OPEN PORTS SCANNING", fg=CYAN, bg=BG_CARD,
                 font=("Arial", 9, "bold")).pack(anchor="nw", padx=10, pady=3)
        self.ports_data = ScrollableLog(frame_bottom, fg=CYAN, bg=BG_CARD,
                                         font=("Consolas", 8))
        self.ports_data.pack(fill="both", expand=True, padx=6, pady=(0, 4))

        # ── Stats box (أسفل يمين) ──
        frame_stats = tk.Frame(self, bg=BG_CARD,
                               highlightbackground=CYAN_DIM, highlightthickness=1)
        frame_stats.place(x=628, y=364, width=152, height=58)
        self._stat_lbl = tk.Label(frame_stats,
                                   text="Total Ports Scan  20-1025\nOpen Ports          -\nInsecure Ports      -",
                                   fg=CYAN, bg=BG_CARD,
                                   font=("Consolas", 7), justify="left", anchor="w")
        self._stat_lbl.pack(fill="both", padx=6, pady=4)

        # ── أزرار ──
        neon_btn(self, "Stop",
                 lambda: self.controller.stop_web_scan(),
                 color=MAGENTA, w=120, h=38).place(x=W//2 - 60, y=430)

    def on_show(self):
        """بيتنادى كل ما الشاشة تظهر — يبدأ تحديث الـ stats box."""
        self._refresh_stats()

    def _refresh_stats(self):
        """بيحسب الـ open/insecure ports من الـ scan_output الحالي كل 2 ثانية."""
        try:
            if not _WA_LOADED or _wa is None:
                return
            ports = list(_wa.scan_output)
            total_open     = len(ports)
            total_insecure = sum(1 for p in ports if p.startswith("Alert"))
            self._stat_lbl.config(
                text=(f"Total Ports Scan  20-1025\n"
                      f"Open Ports          {total_open}\n"
                      f"Insecure Ports      {total_insecure}")
            )
            self.after(2000, self._refresh_stats)
        except Exception:
            pass
class PcapResultScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "Network Forensics (PCAP Analysis)", MAGENTA, BG_DEEP, ("Arial", 16, "bold"), x=40, y=10, anchor="w", justify="left")

        # 1.(PCAP Packet Analysis)
        frame_left = tk.Frame(self, bg=BG_CARD, highlightbackground=MAGENTA, highlightthickness=2)
        frame_left.place(x=40, y=50, width=400, height=300)
        tk.Label(frame_left, text="PACKET ANALYSIS (PCAP)", fg=MAGENTA, bg=BG_CARD, font=("Arial", 10, "bold")).pack(anchor="nw", padx=10, pady=5)
        self.pcap_data = ScrollableLog(frame_left, fg=WHITE, bg=BG_CARD)
        self.pcap_data.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # 2.(Forensics Alerts)
        frame_right = tk.Frame(self, bg=BG_CARD, highlightbackground=MAGENTA, highlightthickness=2)
        frame_right.place(x=460, y=50, width=300, height=300)
        tk.Label(frame_right, text="FORENSICS ALERTS", fg=MAGENTA, bg=BG_CARD, font=("Arial", 10, "bold")).pack(anchor="nw", padx=10, pady=5)
        self.forensics_alerts = ScrollableLog(frame_right, fg=WHITE, bg=BG_CARD)
        self.forensics_alerts.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # 3.(Log/Summary)
        frame_bottom = tk.Frame(self, bg=BG_CARD, highlightbackground=MAGENTA, highlightthickness=2)
        frame_bottom.place(x=40, y=360, width=720, height=60)
        self.log_data = tk.Label(frame_bottom, text="PCAP LOG SUMMARY: ...", fg=MAGENTA, bg=BG_CARD, font=("Arial", 10, "bold"))
        self.log_data.pack(pady=20)

        # (Back و Next)
        neon_btn(self, "Back", lambda: self.controller.show_frame("ScenarioScreen"), color=CYAN, w=120, h=40).place(x=250, y=430)
        neon_btn(self, "Next to Report", lambda: self.controller.show_frame("ReportScreen"), color=MAGENTA, w=140, h=40).place(x=400, y=430)

    def populate(self, results):
 
        self.pcap_data.set_text(f"Filename: {results.get('file', 'N/A')}\nCaptured packets: {results.get('count', '0')}")
        self.forensics_alerts.set_text(f"{results.get('alerts', 'None')}")
        self.log_data.config(text=f"SUMMARY: {results.get('summary', 'Ready')}")


#  SCREEN — HELP

class HelpScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._active_tab = None
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "Help Center", CYAN, BG_DEEP, ("Arial", 20, "bold"),
                         x=40, y=14, width=720, anchor="center", justify="center")

        # ── Tab bar ───
        tab_bar = tk.Frame(self, bg=BG_CARD, highlightbackground=CYAN_DIM, highlightthickness=1)
        tab_bar.place(x=30, y=58, width=740, height=50)

        self._tab_btns = {}
        for i, (lbl, key) in enumerate([("📖  Features", "features"), ("📞  Contact Us", "contact")]):
            b = tk.Label(tab_bar, text=lbl, fg=GREY, bg=BG_CARD,
                         font=("Arial", 12, "bold"), cursor="hand2", anchor="center")
            b.place(x=i*370, y=0, width=370, height=50)
            b.bind("<Button-1>", lambda e, k=key: self._show_tab(k))
            self._tab_btns[key] = b

        self._content = tk.Frame(self, bg=BG_CARD,
                                  highlightbackground=CYAN_DIM, highlightthickness=1)
        self._content.place(x=30, y=108, width=740, height=310)

        neon_btn(self, "Back", lambda: self.controller.show_frame("WelcomeScreen"),
                 color=MAGENTA, w=120, h=44).place(x=650, y=426)
        self._show_tab("features")

    def _show_tab(self, key):
        self._active_tab = key
        for k, b in self._tab_btns.items():
            b.config(fg=BG_DEEP if k == key else GREY,
                     bg=CYAN    if k == key else BG_CARD)
        for w in self._content.winfo_children():
            w.destroy()
        if key == "features":
            self._build_features()
        else:
            self._build_contact()

    def _build_features(self):
        p = self._content
        canvas = tk.Canvas(p, bg=BG_CARD, highlightthickness=0)
        sb = tk.Scrollbar(p, orient="vertical", command=canvas.yview,
                          bg=BG_CARD, troughcolor=BG_DEEP,
                          activebackground=CYAN, bd=0, relief="flat", width=8)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=BG_CARD)
        win = canvas.create_window((0, 0), window=inner, anchor="nw")

        features = [
            ("🌐  Network Mode",
             "Scan your local network for connected devices and open ports.\n"
             "• Discovery Scenario   → Live packet sniffing on a selected interface.\n"
             "• Incident Response    → Upload a PCAP file for deep forensics analysis.\n"
             "• Results show Alerts, Packet data, and Open Ports in real-time."),
            ("🔍  Web Mode",
             "Analyse any URL for common web vulnerabilities.\n"
             "• Discovery Scenario   → Active scan (XSS, IDOR, CSRF, CORS, DOM XSS).\n"
             "• Passive Scenario     → Upload a log file for offline analysis.\n"
             "• Results include Risk Score, SSL status, and Security Status."),
            ("📡  Network Settings",
             "Configure your Wi-Fi before starting a network scan.\n"
             "• Toggle Wi-Fi on to scan available networks.\n"
             "• Select a network and enter the password to connect.\n"
             "• Once connected the app proceeds to scenario selection."),
            ("⚙️  Scenario Selection",
             "Choose the scan strategy that matches your goal.\n"
             "• Discovery            → Detect threats on a live network in real-time.\n"
             "• Incident Response    → Investigate an existing capture (PCAP / log file).\n"
             "• Your choice affects which tools and modules are activated."),
            ("📊  Report Screen",
             "Review the full scan summary after scanning completes.\n"
             "• Shows URLs found, Alerts, Security Status, Risk Score, SSL, IP.\n"
             "• Click \'Send Report\' to email a PDF copy to any address.\n"
             "• The PDF is auto-generated and attached to the email."),
            ("📤  Send Report",
             "Send the scan results as a professional PDF report.\n"
             "• Enter any email address and click Send.\n"
             "• The report is generated automatically from the latest scan.\n"
             "• Check your inbox — delivery takes just a few seconds."),
        ]

        for title, desc in features:
            row = tk.Frame(inner, bg=BG_FIELD,
                           highlightbackground=CYAN_DIM, highlightthickness=1)
            row.pack(fill="x", padx=10, pady=5)
            hdr = tk.Frame(row, bg=BG_FIELD, cursor="hand2")
            hdr.pack(fill="x")
            title_lbl = tk.Label(hdr, text=title, fg=CYAN, bg=BG_FIELD,
                                  font=("Arial", 12, "bold"), anchor="w")
            title_lbl.pack(side="left", padx=14, pady=10)
            arrow = tk.Label(hdr, text="▶", fg=CYAN_DIM, bg=BG_FIELD, font=("Arial", 10))
            arrow.pack(side="right", padx=14)
            body_lbl = tk.Label(row, text=desc, fg=WHITE, bg=BG_DEEP,
                                 font=("Arial", 10), anchor="nw",
                                 justify="left", wraplength=670)
            state = {"open": False}

            def _toggle(e=None, r=row, b=body_lbl, a=arrow, s=state, c=canvas):
                if s["open"]:
                    b.pack_forget()
                    a.config(text="▶", fg=CYAN_DIM)
                    s["open"] = False
                else:
                    b.pack(fill="x", padx=14, pady=(0, 10))
                    a.config(text="▼", fg=CYAN)
                    s["open"] = True
                c.after(10, lambda: c.configure(scrollregion=c.bbox("all")))

            for w in [hdr, title_lbl, arrow]:
                w.bind("<Button-1>", _toggle)

        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        for _w in (canvas, inner):
            _w.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
            _w.bind("<Button-4>",   lambda e: canvas.yview_scroll(-1, "units"))
            _w.bind("<Button-5>",   lambda e: canvas.yview_scroll(1, "units"))

    def _build_contact(self):
        p = self._content
        contacts = [
            ("📧", "Email Support",   "support@forenxa.io",      "Send us an email — we reply within 24 hours."),
            ("📞", "Phone Support",   "+20 100 000 0000",         "Available Sat – Thu  |  9 AM – 5 PM"),
            ("💬", "Send a Comment",  "Write directly from here", "Use the box below to send us feedback instantly."),
        ]
        for i, (icon, title, value, sub) in enumerate(contacts):
            card = tk.Frame(p, bg=BG_FIELD,
                            highlightbackground=CYAN_DIM, highlightthickness=1)
            card.place(x=14, y=10+i*74, width=710, height=62)
            tk.Label(card, text=icon,  fg=CYAN,  bg=BG_FIELD, font=("Arial", 20)).place(x=14, y=10)
            tk.Label(card, text=title, fg=CYAN,  bg=BG_FIELD,
                     font=("Arial", 11, "bold"), anchor="w").place(x=56, y=8,  width=300)
            tk.Label(card, text=value, fg=WHITE, bg=BG_FIELD,
                     font=("Arial", 10, "bold"), anchor="w").place(x=56, y=28, width=380)
            tk.Label(card, text=sub,   fg=GREY,  bg=BG_FIELD,
                     font=("Arial", 9), anchor="e").place(x=340, y=18, width=356)

        tk.Frame(p, bg=CYAN_DIM, height=1).place(x=14, y=240, width=710)
        tk.Label(p, text="Send a Comment", fg=CYAN, bg=BG_CARD,
                 font=("Arial", 11, "bold"), anchor="w").place(x=14, y=248)

        self._comment_var = tk.StringVar()
        ef = tk.Frame(p, bg=BG_FIELD, highlightbackground=CYAN, highlightthickness=1)
        ef.place(x=14, y=272, width=590, height=36)
        self._ce = tk.Entry(ef, textvariable=self._comment_var,
                             font=("Arial", 12), fg=GREY, bg=BG_FIELD,
                             insertbackground=CYAN, relief="flat", bd=0)
        self._ce.pack(fill="both", padx=10, pady=8)
        enable_copy_paste(self._ce)
        self._ce.insert(0, "Write your comment…")
        self._ce.bind("<FocusIn>",
                      lambda e: (self._ce.delete(0, "end"), self._ce.config(fg=WHITE))
                      if self._comment_var.get() == "Write your comment…" else None)
        self._ce.bind("<FocusOut>",
                      lambda e: (self._ce.insert(0, "Write your comment…"), self._ce.config(fg=GREY))
                      if not self._comment_var.get() else None)
        self._c_status = tk.Label(p, text="", fg=CYAN, bg=BG_CARD, font=("Arial", 9))
        self._c_status.place(x=14, y=312, width=590)
        neon_btn(p, "Submit", self._submit_comment, color=CYAN, w=110, h=36).place(x=618, y=272)

    def _submit_comment(self):
        txt = self._comment_var.get().strip()
        if not txt or txt == "Write your comment…":
            self._c_status.config(text="⚠  Please write a comment first.", fg=MAGENTA)
            return
        def _worker():
            try:
                msg = MIMEMultipart()
                msg["From"]    = formataddr((SENDER_NAME, SENDER_EMAIL))
                msg["To"]      = SENDER_EMAIL
                msg["Subject"] = "Forenxa – User Comment"
                msg.attach(MIMEText(f"User Comment:\n\n{txt}", "plain"))
                with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as s:
                    s.login(SENDER_EMAIL, SENDER_PASSWORD)
                    s.sendmail(SENDER_EMAIL, SENDER_EMAIL, msg.as_string())
                self.controller.schedule_ui(0, lambda: self._c_status.config(
                    text="✔  Comment sent!", fg=GREEN))
            except Exception as ex:
                self.controller.schedule_ui(0, lambda: self._c_status.config(
                    text=f"✖  Failed: {ex}", fg=MAGENTA))
        self._c_status.config(text="⏳  Sending…", fg=CYAN)
        threading.Thread(target=_worker, daemon=True).start()

    def on_show(self):
        self._show_tab("features")


#  SCREEN — SETTINGS

class SettingsScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._gmail_var  = tk.StringVar(value=SENDER_EMAIL)
        self._lang_var   = tk.StringVar(value="English")
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "Settings", CYAN, BG_DEEP, ("Arial", 20, "bold"),
                         x=40, y=14, width=720, anchor="center", justify="center")

        tab_bar = tk.Frame(self, bg=BG_CARD, highlightbackground=CYAN_DIM, highlightthickness=1)
        tab_bar.place(x=30, y=58, width=740, height=50)

        self._tab_btns = {}
        for i, (lbl, key) in enumerate([("📧  Gmail","gmail"),("🔔  Notifications","notif"),
                                         ("🌍  Language","lang"),("ℹ️  About","about")]):
            b = tk.Label(tab_bar, text=lbl, fg=GREY, bg=BG_CARD,
                         font=("Arial", 11, "bold"), cursor="hand2", anchor="center")
            b.place(x=i*185, y=0, width=185, height=50)
            b.bind("<Button-1>", lambda e, k=key: self._show_tab(k))
            self._tab_btns[key] = b

        self._content = tk.Frame(self, bg=BG_CARD,
                                  highlightbackground=CYAN_DIM, highlightthickness=1)
        self._content.place(x=30, y=108, width=740, height=310)

        neon_btn(self, "Back", lambda: self.controller.show_frame("WelcomeScreen"),
                 color=MAGENTA, w=120, h=44).place(x=650, y=426)
        self._show_tab("gmail")

    def _show_tab(self, key):
        for k, b in self._tab_btns.items():
            b.config(fg=BG_DEEP if k == key else GREY,
                     bg=CYAN    if k == key else BG_CARD)
        for w in self._content.winfo_children():
            w.destroy()
        {"gmail": self._build_gmail, "notif": self._build_notif,
         "lang": self._build_lang,   "about": self._build_about}[key]()

    # ── Gmail tab ───
    def _build_gmail(self):
        p = self._content
        tk.Label(p, text="Connected Gmail Account", fg=CYAN, bg=BG_CARD,
                 font=("Arial", 13, "bold"), anchor="w").place(x=24, y=20)
        tk.Frame(p, bg=CYAN_DIM, height=1).place(x=24, y=48, width=690)

        acc_card = tk.Frame(p, bg=BG_FIELD, highlightbackground=CYAN, highlightthickness=1)
        acc_card.place(x=24, y=58, width=690, height=60)
        tk.Label(acc_card, text="📧", fg=CYAN, bg=BG_FIELD, font=("Arial", 22)).place(x=14, y=12)
        tk.Label(acc_card, textvariable=self._gmail_var, fg=WHITE, bg=BG_FIELD,
                 font=("Arial", 13, "bold"), anchor="w").place(x=54, y=18, width=500)
        tk.Label(acc_card, text="● Active", fg=GREEN, bg=BG_FIELD,
                 font=("Arial", 9)).place(x=600, y=22)

        tk.Label(p, text="Change Account", fg=GREY, bg=BG_CARD,
                 font=("Arial", 11), anchor="w").place(x=24, y=134)

        self._new_gmail_var = tk.StringVar()
        ef1 = tk.Frame(p, bg=BG_FIELD, highlightbackground=CYAN_DIM, highlightthickness=1)
        ef1.place(x=24, y=158, width=690, height=44)
        e1 = tk.Entry(ef1, textvariable=self._new_gmail_var,
                      font=("Arial", 13), fg=GREY, bg=BG_FIELD,
                      insertbackground=CYAN, relief="flat", bd=0)
        e1.pack(fill="both", padx=12, pady=10)
        enable_copy_paste(e1)
        e1.insert(0, "New Gmail address")
        e1.bind("<FocusIn>",  lambda e: (e1.delete(0,"end"), e1.config(fg=WHITE))
                if self._new_gmail_var.get()=="New Gmail address" else None)
        e1.bind("<FocusOut>", lambda e: (e1.insert(0,"New Gmail address"), e1.config(fg=GREY))
                if not self._new_gmail_var.get() else None)

        self._new_pass_var = tk.StringVar()
        ef2 = tk.Frame(p, bg=BG_FIELD, highlightbackground=CYAN_DIM, highlightthickness=1)
        ef2.place(x=24, y=210, width=690, height=44)
        e2 = tk.Entry(ef2, textvariable=self._new_pass_var,
                      font=("Arial", 13), fg=GREY, bg=BG_FIELD,
                      insertbackground=CYAN, relief="flat", bd=0)
        e2.pack(fill="both", padx=12, pady=10)
        enable_copy_paste(e2)
        PH2 = "App Password (16-digit Gmail App Password)"
        e2.insert(0, PH2)
        e2.bind("<FocusIn>",  lambda e: (e2.delete(0,"end"), e2.config(fg=WHITE, show="•"))
                if self._new_pass_var.get()==PH2 else None)
        e2.bind("<FocusOut>", lambda e: (e2.insert(0,PH2), e2.config(fg=GREY, show=""))
                if not self._new_pass_var.get() else None)

        self._gmail_status = tk.Label(p, text="", fg=CYAN, bg=BG_CARD, font=("Arial", 10))
        self._gmail_status.place(x=24, y=262, width=690)
        neon_btn(p, "Save Account", self._save_gmail, color=CYAN, w=160, h=44).place(x=266, y=256)
        tk.Label(p, text="⚠  Use a Gmail App Password, not your regular password.",
                 fg=GREY, bg=BG_CARD, font=("Arial", 9)).place(x=24, y=284, width=690)

    def _save_gmail(self):
        global SENDER_EMAIL, SENDER_PASSWORD
        new_email = self._new_gmail_var.get().strip()
        new_pass  = self._new_pass_var.get().strip()
        if not new_email or new_email == "New Gmail address":
            self._gmail_status.config(text="⚠  Enter a Gmail address.", fg=MAGENTA); return
        if not EMAIL_RE.match(new_email):
            self._gmail_status.config(text="⚠  Invalid email format.", fg=MAGENTA); return
        PH2 = "App Password (16-digit Gmail App Password)"
        if not new_pass or new_pass == PH2:
            self._gmail_status.config(text="⚠  Enter the App Password.", fg=MAGENTA); return
        SENDER_EMAIL    = new_email
        SENDER_PASSWORD = new_pass
        self._gmail_var.set(new_email)
        self._gmail_status.config(text="✔  Account updated successfully!", fg=GREEN)

    # ── Notifications tab ───
    def _build_notif(self):
        p = self._content
        tk.Label(p, text="Notification Preferences", fg=CYAN, bg=BG_CARD,
                 font=("Arial", 13, "bold"), anchor="w").place(x=24, y=20)
        tk.Frame(p, bg=CYAN_DIM, height=1).place(x=24, y=48, width=690)

        items = [
            ("Scan Completed Alert",      "Show a notification when a scan finishes."),
            ("New Threat Detected",       "Alert immediately when a threat is found."),
            ("Report Sent Confirmation",  "Notify when the PDF report is sent successfully."),
            ("Network Connection Status", "Show notification on Wi-Fi connect / disconnect."),
        ]
        self._notif_vars = {}
        for i, (title, sub) in enumerate(items):
            row = tk.Frame(p, bg=BG_FIELD, highlightbackground=CYAN_DIM, highlightthickness=1)
            row.place(x=24, y=58+i*58, width=690, height=50)
            tk.Label(row, text=title, fg=WHITE, bg=BG_FIELD,
                     font=("Arial", 11, "bold"), anchor="w").place(x=14, y=6,  width=580)
            tk.Label(row, text=sub,   fg=GREY,  bg=BG_FIELD,
                     font=("Arial", 9),  anchor="w").place(x=14, y=28, width=580)
            sw = ToggleSwitch(row, on=True, on_color=CYAN, off_color=GREY,
                              on_change=lambda state, t=title: None)
            sw.place(x=636, y=12)

    # ── Language tab ───
    def _build_lang(self):
        p = self._content
        tk.Label(p, text="Display Language", fg=CYAN, bg=BG_CARD,
                 font=("Arial", 13, "bold"), anchor="w").place(x=24, y=20)
        tk.Frame(p, bg=CYAN_DIM, height=1).place(x=24, y=48, width=690)

        langs = [
            ("🇬🇧", "English", "English",  "Default application language."),
            ("🇸🇦", "Arabic",  "Arabic",   "واجهة كاملة باللغة العربية — قريباً"),
            ("🇫🇷", "French",  "French",   "Interface en français — bientôt disponible"),
            ("🇩🇪", "German",  "German",   "Deutsche Oberfläche — demnächst verfügbar"),
        ]
        self._lang_status = tk.Label(p, text="", fg=CYAN, bg=BG_CARD, font=("Arial", 10))
        self._lang_status.place(x=24, y=290, width=690)

        for i, (flag, name, val, desc) in enumerate(langs):
            row = tk.Frame(p, bg=BG_FIELD, highlightbackground=CYAN_DIM, highlightthickness=1,
                           cursor="hand2")
            row.place(x=24, y=58+i*56, width=690, height=48)
            tk.Label(row, text=flag, fg=WHITE, bg=BG_FIELD, font=("Arial", 18)).place(x=14, y=8)
            tk.Label(row, text=name, fg=WHITE, bg=BG_FIELD,
                     font=("Arial", 12, "bold"), anchor="w").place(x=54, y=6,  width=200)
            tk.Label(row, text=desc, fg=GREY,  bg=BG_FIELD,
                     font=("Arial", 9),  anchor="w").place(x=54, y=26, width=400)
            ind = tk.Label(row, text="✔" if self._lang_var.get()==val else "",
                           fg=CYAN, bg=BG_FIELD, font=("Arial", 16))
            ind.place(x=650, y=10)

            def _sel(e=None, v=val, n=name):
                self._lang_var.set(v)
                msg = f"✔  Language set to {n}." if v=="English"                       else f"✔  Language set to {n}  (full support coming soon)"
                self._lang_status.config(text=msg, fg=GREEN)
                self._show_tab("lang")

            for w in [row] + list(row.winfo_children()):
                w.bind("<Button-1>", _sel)

    # ── About tab ───
    def _build_about(self):
        p = self._content
        tk.Label(p, text="FORENXA", fg=CYAN, bg=BG_CARD,
                 font=("Arial", 30, "bold")).place(x=0, y=20, width=740)
        tk.Label(p, text="Security Analysis System", fg=GREY, bg=BG_CARD,
                 font=("Arial", 11)).place(x=0, y=62, width=740)
        tk.Frame(p, bg=CYAN_DIM, height=1).place(x=24, y=100, width=690)

        rows = [
            ("Version",       "1.0.0  (Release Candidate)"),
            ("Platform",      "Raspberry Pi 4  /  Linux"),
            ("Python",        "3.10+"),
            ("UI Framework",  "Tkinter"),
            ("Scan Engine",   "Netscan + WebScan (custom modules)"),
            ("Report Format", "PDF  (fpdf2)"),
            ("Developer",     "Forenxa Security Team"),
            ("Contact",       "support@forenxa.io"),
        ]
        for i, (label, value) in enumerate(rows):
            bg = "#0C0C1C" if i % 2 == 0 else BG_FIELD
            row = tk.Frame(p, bg=bg)
            row.place(x=24, y=108+i*24, width=690, height=24)
            tk.Label(row, text=label, fg=GREY,  bg=bg,
                     font=("Arial", 10), anchor="w", width=18).pack(side="left", padx=10)
            tk.Label(row, text=value, fg=WHITE, bg=bg,
                     font=("Arial", 10, "bold"), anchor="w").pack(side="left")

        tk.Label(p, text="© 2025 Forenxa. All rights reserved.",
                 fg=CYAN_DIM, bg=BG_CARD, font=("Arial", 8)).place(x=0, y=302, width=740)

    def on_show(self):
        self._show_tab("gmail")


#  SCREEN 6 — EMAIL / SEND REPORT

class EmailScreen(BaseScreen):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._build()

    def _build(self):
        self._set_bg()
        title_with_rules(self, "Send Report with", CYAN, BG_DEEP, ("Arial", 22, "bold"), x=40, y=36, width=500, anchor="w", justify="left")

        ef = tk.Frame(self, bg=BG_FIELD, highlightbackground=CYAN, highlightthickness=2)
        ef.place(x=40, y=104, width=720, height=58)
        self._email_var = tk.StringVar()
        self._email_e   = tk.Entry(ef, textvariable=self._email_var, font=("Arial", 14), fg=GREY, bg=BG_FIELD, insertbackground=CYAN, relief="flat", bd=0)
        self._email_e.pack(fill="both", padx=16, pady=14)
        enable_copy_paste(self._email_e)
        self._email_e.insert(0, "Email")
        self._email_e.bind("<FocusIn>",  self._clear_ph)
        self._email_e.bind("<FocusOut>", self._set_ph)

        self._status = tk.Label(self, text="", fg=CYAN, bg=BG_DEEP, font=F_BODY)
        self._status.place(x=0, y=174, width=W)

        neon_btn(self, "Send", self._send, color=CYAN, w=140, h=48).place(x=W//2 - 70, y=244)
        neon_btn(self, "Back", lambda: self.controller.show_frame("ReportScreen"), color=MAGENTA, w=120, h=44).place(x=W//2 - 60, y=408)

    def on_show(self):
        self._status.config(text="")
        self._email_e.delete(0, "end")
        self._email_e.insert(0, "Email")
        self._email_e.config(fg=GREY)

    def _clear_ph(self, e=None):
        if self._email_e.get() == "Email":
            self._email_e.delete(0, "end")
            self._email_e.config(fg=CYAN)

    def _set_ph(self, e=None):
        if not self._email_var.get():
            self._email_e.insert(0, "Email")
            self._email_e.config(fg=GREY)

    def _send(self):
        email = self._email_var.get().strip()
        if not email or email == "Email":
            self._status.config(text="⚠  Please enter an email address.", fg=MAGENTA)
            return
        if not EMAIL_RE.match(email):
            self._status.config(text="⚠  Invalid email address.", fg=MAGENTA)
            return

        self._status.config(text="⏳  Generating report & sending...", fg=CYAN)

        results = self.controller.scan_results #هنا بناخد البيانات من الcontroller
        url     = self.controller.current_url.get()

        def _worker(): 
            ok, info = self.controller.send_report_email(email, results, url)#هنا الكود بيخرج من ال
            if ok:
                self.controller.schedule_ui(
                    0, lambda: self._status.config(text="✔  Report sent successfully!", fg=GREEN)
                )
            else:
                self.controller.schedule_ui(
                    0, lambda: self._status.config(text=f"✖  Failed: {info}", fg=MAGENTA)
                )

        threading.Thread(target=_worker, daemon=True).start()

# بيشغل الGUI من هنا 
if __name__ == "__main__":
    app = SecurityApp()
    app.mainloop()