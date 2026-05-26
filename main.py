# main.py
# PhishGuard V5 - Redesigned UI
# Theme: Redacted Document / Intelligence File
# Dark warm charcoal + amber accent, single-column, stamp-style risk verdict

import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import os

from detector import analyze_email
from export import export_txt, export_csv

# -----------------------------------------------------------
# THEME
# -----------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# -----------------------------------------------------------
# COLOUR PALETTE — Warm dark, amber accent
# -----------------------------------------------------------
C_BG          = "#1C1A17"   # Warm charcoal (not cold black)
C_SURFACE     = "#242119"   # Slightly lighter warm surface
C_SURFACE2    = "#2C2923"   # Card interior
C_SURFACE3    = "#333028"   # Hover / subtle
C_BORDER      = "#3D3A30"   # Warm grey border
C_BORDER2     = "#54503F"   # Brighter border
C_TEXT        = "#E8E2D4"   # Warm white text
C_TEXT2       = "#A09880"   # Secondary text
C_TEXT3       = "#635E4E"   # Placeholder / disabled
C_AMBER       = "#D4891A"   # Primary amber accent
C_AMBER_DARK  = "#B8740F"   # Amber hover
C_AMBER_DIM   = "#2A2316"   # Very dim amber bg for highlights
C_SAFE        = "#4E9E6A"   # Muted green
C_SAFE_BG     = "#1A2B20"   # Green tinted bg
C_MEDIUM      = "#C4922A"   # Amber warning
C_MEDIUM_BG   = "#28210F"   # Amber tinted bg
C_HIGH        = "#C45A3A"   # Burnt orange-red
C_HIGH_BG     = "#2A1A14"   # Red tinted bg
C_BTN         = "#FFFFFF"   # Button label


def get_risk_colors(risk: str):
    """Returns (text_color, bg_color, border_color) for risk level."""
    return {
        "SAFE":   (C_SAFE,   C_SAFE_BG,   C_SAFE),
        "MEDIUM": (C_MEDIUM, C_MEDIUM_BG, C_MEDIUM),
        "HIGH":   (C_HIGH,   C_HIGH_BG,   C_HIGH),
    }.get(risk, (C_TEXT3, C_SURFACE, C_BORDER))


# -----------------------------------------------------------
# MAIN APP
# -----------------------------------------------------------
class PhishGuardApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("PhishGuard — Phishing Email Analyzer")
        self.geometry("800x840")
        self.minsize(720, 700)
        self.configure(fg_color=C_BG)
        self.resizable(True, True)

        self.last_result = None
        self.last_email  = ""

        self._build_ui()

    # --------------------------------------------------------
    # FULL UI BUILD
    # --------------------------------------------------------
    def _build_ui(self):
        self.scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=C_BG,
            scrollbar_button_color=C_BORDER,
            scrollbar_button_hover_color=C_BORDER2
        )
        self.scroll.pack(fill="both", expand=True)

        self._build_header()
        self._build_input_card()
        self._build_controls()
        self._build_verdict_banner()
        self._build_findings_card()
        self._build_footer()

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------
    def _build_header(self):
        header = ctk.CTkFrame(self.scroll, fg_color=C_SURFACE, corner_radius=0)
        header.pack(fill="x", pady=(0, 2))

        # Top amber stripe
        ctk.CTkFrame(header, fg_color=C_AMBER, height=3, corner_radius=0).pack(fill="x", side="top")

        inner = ctk.CTkFrame(header, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=16)

        # Left — title block
        left = ctk.CTkFrame(inner, fg_color="transparent")
        left.pack(side="left")

        # # Classification tag
        # ctk.CTkLabel(
        #     left,
        #     text="[ THREAT ANALYSIS UTILITY ]",
        #     font=ctk.CTkFont(family="Courier New", size=9, weight="bold"),
        #     text_color=C_AMBER
        # ).pack(anchor="w")

        ctk.CTkLabel(
            left,
            text="PHISHGUARD",
            font=ctk.CTkFont(family="Courier New", size=30, weight="bold"),
            text_color=C_TEXT
        ).pack(anchor="w")

        ctk.CTkLabel(
            left,
            text="Email Phishing Detection System",
            font=ctk.CTkFont(family="Courier New", size=12),
            text_color=C_TEXT3
        ).pack(anchor="w")

        # Right — live status
        right = ctk.CTkFrame(inner, fg_color=C_AMBER_DIM, corner_radius=4)
        right.pack(side="right", anchor="center", padx=4, pady=4)

        self.status_dot = ctk.CTkLabel(
            right,
            text="◉  READY",
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            text_color=C_AMBER
        )
        self.status_dot.pack(padx=16, pady=10)

    # --------------------------------------------------------
    # INPUT CARD
    # --------------------------------------------------------
    def _build_input_card(self):
        card = ctk.CTkFrame(
            self.scroll,
            fg_color=C_SURFACE,
            corner_radius=6,
            border_width=1,
            border_color=C_BORDER
        )
        card.pack(fill="x", padx=24, pady=(14, 6))

        # Card header row
        hdr = ctk.CTkFrame(card, fg_color=C_SURFACE2, corner_radius=0)
        hdr.pack(fill="x")

        ctk.CTkLabel(
            hdr,
            text="  EMAIL INPUT",
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            text_color=C_AMBER,
            anchor="w"
        ).pack(side="left", padx=14, pady=8)

        ctk.CTkLabel(
            hdr,
            text="paste full email content  ",
            font=ctk.CTkFont(family="Courier New", size=11),
            text_color=C_TEXT3,
            anchor="e"
        ).pack(side="right", pady=8)

        # Textarea
        self.email_input = ctk.CTkTextbox(
            card,
            height=190,
            fg_color=C_BG,
            text_color=C_TEXT3,
            border_color=C_BORDER,
            border_width=1,
            font=ctk.CTkFont(family="Courier New", size=12),
            corner_radius=4,
            wrap="word",
            scrollbar_button_color=C_BORDER2
        )
        self.email_input.pack(fill="x", padx=14, pady=14)
        self.email_input.insert("0.0", "Paste the suspicious email content here...")
        self.email_input.bind("<FocusIn>",  self._clear_placeholder)
        self.email_input.bind("<FocusOut>", self._restore_placeholder)

    def _clear_placeholder(self, event=None):
        if self.email_input.get("0.0", "end").strip() == "Paste the suspicious email content here...":
            self.email_input.delete("0.0", "end")
            self.email_input.configure(text_color=C_TEXT)

    def _restore_placeholder(self, event=None):
        if not self.email_input.get("0.0", "end").strip():
            self.email_input.configure(text_color=C_TEXT3)
            self.email_input.insert("0.0", "Paste the suspicious email content here...")

    # --------------------------------------------------------
    # CONTROL BUTTONS
    # --------------------------------------------------------
    def _build_controls(self):
        row = ctk.CTkFrame(self.scroll, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=(0, 10))

        # Primary
        ctk.CTkButton(
            row,
            text="▶  RUN ANALYSIS",
            command=self._run_analysis,
            fg_color=C_AMBER,
            hover_color=C_AMBER_DARK,
            text_color="#1C1A17",
            font=ctk.CTkFont(family="Courier New", size=13, weight="bold"),
            corner_radius=4,
            height=40,
            width=190
        ).pack(side="left", padx=(0, 10))

        # Secondaries
        for label, cmd in [
            ("↑ UPLOAD",     self._upload_file),
            (" CLEAR",      self._clear_all),
            ("↓ EXPORT TXT", self._export_txt),
            ("↓ EXPORT CSV", self._export_csv),
        ]:
            ctk.CTkButton(
                row,
                text=label,
                command=cmd,
                fg_color=C_SURFACE,
                hover_color=C_SURFACE3,
                text_color=C_TEXT2,
                border_color=C_BORDER2,
                border_width=1,
                font=ctk.CTkFont(family="Courier New", size=11),
                corner_radius=4,
                height=40,
                width=118
            ).pack(side="left", padx=(0, 6))

    # --------------------------------------------------------
    # VERDICT BANNER — Stamped result centrepiece
    # --------------------------------------------------------
    def _build_verdict_banner(self):
        self.verdict_card = ctk.CTkFrame(
            self.scroll,
            fg_color=C_SURFACE,
            corner_radius=6,
            border_width=1,
            border_color=C_BORDER
        )
        self.verdict_card.pack(fill="x", padx=24, pady=(0, 6))

        # Top label bar
        top_bar = ctk.CTkFrame(self.verdict_card, fg_color=C_SURFACE2, corner_radius=0)
        top_bar.pack(fill="x")

        ctk.CTkLabel(
            top_bar,
            text="  ANALYSIS VERDICT",
            font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
            text_color=C_AMBER
        ).pack(side="left", padx=14, pady=8)

        # Content row
        content = ctk.CTkFrame(self.verdict_card, fg_color="transparent")
        content.pack(fill="x", padx=20, pady=18)

        # Left — classification stamp
        left = ctk.CTkFrame(content, fg_color="transparent")
        left.pack(side="left")

        ctk.CTkLabel(
            left,
            text="THREAT LEVEL",
            font=ctk.CTkFont(family="Courier New", size=10),
            text_color=C_TEXT3
        ).pack(anchor="w")

        self.risk_value = ctk.CTkLabel(
            left,
            text="PENDING",
            font=ctk.CTkFont(family="Courier New", size=42, weight="bold"),
            text_color=C_TEXT3
        )
        self.risk_value.pack(anchor="w")

        # Separator
        ctk.CTkFrame(content, fg_color=C_BORDER, width=1).pack(
            side="left", fill="y", padx=28, pady=4
        )

        # Middle — score
        mid = ctk.CTkFrame(content, fg_color="transparent")
        mid.pack(side="left")

        ctk.CTkLabel(
            mid,
            text="RISK SCORE",
            font=ctk.CTkFont(family="Courier New", size=10),
            text_color=C_TEXT3
        ).pack(anchor="w")

        self.score_value = ctk.CTkLabel(
            mid,
            text="— / 10",
            font=ctk.CTkFont(family="Courier New", size=42, weight="bold"),
            text_color=C_TEXT3
        )
        self.score_value.pack(anchor="w")

        # Right — recommended action
        right = ctk.CTkFrame(content, fg_color="transparent")
        right.pack(side="right", fill="both", expand=True)

        ctk.CTkLabel(
            right,
            text="RECOMMENDED ACTION",
            font=ctk.CTkFont(family="Courier New", size=10),
            text_color=C_TEXT3,
            anchor="e"
        ).pack(anchor="e")

        self.action_label = ctk.CTkLabel(
            right,
            text="Awaiting email submission.",
            font=ctk.CTkFont(family="Courier New", size=12),
            text_color=C_TEXT3,
            wraplength=270,
            justify="right",
            anchor="e"
        )
        self.action_label.pack(anchor="e", pady=(6, 0))

    # --------------------------------------------------------
    # FINDINGS CARD
    # --------------------------------------------------------
    def _build_findings_card(self):
        card = ctk.CTkFrame(
            self.scroll,
            fg_color=C_SURFACE,
            corner_radius=6,
            border_width=1,
            border_color=C_BORDER
        )
        card.pack(fill="x", padx=24, pady=(0, 14))

        # Header
        hdr = ctk.CTkFrame(card, fg_color=C_SURFACE2, corner_radius=0)
        hdr.pack(fill="x")

        ctk.CTkLabel(
            hdr,
            text="  DETECTED INDICATORS",
            font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
            text_color=C_AMBER
        ).pack(side="left", padx=14, pady=8)

        self.findings_count = ctk.CTkLabel(
            hdr,
            text="0 flags  ",
            font=ctk.CTkFont(family="Courier New", size=12),
            text_color=C_TEXT3
        )
        self.findings_count.pack(side="right", pady=8)

        # Findings box
        self.findings_box = ctk.CTkTextbox(
            card,
            height=210,
            fg_color=C_BG,
            text_color=C_TEXT,
            border_color=C_BORDER,
            border_width=1,
            font=ctk.CTkFont(family="Courier New", size=12),
            corner_radius=4,
            state="disabled",
            scrollbar_button_color=C_BORDER2,
            wrap="word"
        )
        self.findings_box.pack(fill="x", padx=14, pady=14)

        self._write_findings(["No analysis run yet.  Submit a email above."], idle=True)

    def _write_findings(self, lines: list, idle=False):
        self.findings_box.configure(state="normal")
        self.findings_box.delete("0.0", "end")
        if idle:
            self.findings_box.configure(text_color=C_TEXT3)
            self.findings_box.insert("0.0", f"  {lines[0]}")
        else:
            self.findings_box.configure(text_color=C_TEXT)
            for i, line in enumerate(lines):
                prefix = f"  [{i+1:02d}]  "
                self.findings_box.insert("end", f"{prefix}{line}\n\n")
        self.findings_box.configure(state="disabled")

    # --------------------------------------------------------
    # FOOTER
    # --------------------------------------------------------
    def _build_footer(self):
        footer = ctk.CTkFrame(self.scroll, fg_color="transparent")
        footer.pack(fill="x", padx=24, pady=(0, 20))

        ctk.CTkLabel(
            footer,
            text="PhishGuard  ·  Rule-Based Detection Engine  ·  For Educational Use Only",
            font=ctk.CTkFont(family="Courier New", size=12),
            text_color=C_TEXT3
        ).pack(anchor="center")

    # --------------------------------------------------------
    # ANALYSIS LOGIC
    # --------------------------------------------------------
    def _run_analysis(self):
        email_text = self.email_input.get("0.0", "end").strip()
        if not email_text or email_text == "Paste the suspicious email content here...":
            messagebox.showwarning("PhishGuard", "Please provide email content first.")
            return

        self.last_email = email_text
        self.status_dot.configure(text="◉  SCANNING...", text_color=C_MEDIUM)
        self._write_findings(["Running analysis..."], idle=True)

        def run():
            result = analyze_email(email_text)
            self.last_result = result
            self.after(0, lambda: self._display_results(result))

        threading.Thread(target=run, daemon=True).start()

    def _display_results(self, result: dict):
        risk    = result.get("risk_level", "---")
        score   = result.get("score", 0)
        action  = result.get("suggested_action", "")
        details = result.get("details", [])
        t_color, bg_color, border_color = get_risk_colors(risk)

        # Update verdict card
        self.verdict_card.configure(fg_color=bg_color, border_color=border_color)
        self.risk_value.configure(text=risk, text_color=t_color)
        self.score_value.configure(text=f"{score} / 10", text_color=t_color)
        self.action_label.configure(text=action, text_color=t_color)

        # Update findings
        if details:
            self._write_findings(details)
            self.findings_count.configure(
                text=f"{len(details)} flag(s)  ",
                text_color=t_color
            )
        else:
            self._write_findings(
                ["No suspicious indicators detected. Email appears clean."], idle=True
            )
            self.findings_count.configure(text="0 flags  ", text_color=C_SAFE)

        # Status dot
        dot_map = {
            "SAFE":   ("◉  SAFE",    C_SAFE),
            "MEDIUM": ("◉  CAUTION", C_MEDIUM),
            "HIGH":   ("◉  DANGER",  C_HIGH),
        }
        dot_text, dot_color = dot_map.get(risk, ("◉  DONE", C_TEXT3))
        self.status_dot.configure(text=dot_text, text_color=dot_color)

    # --------------------------------------------------------
    # FILE UPLOAD
    # --------------------------------------------------------
    def _upload_file(self):
        filepath = filedialog.askopenfilename(
            title="Load Email File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not filepath:
            return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            self.email_input.delete("0.0", "end")
            self.email_input.insert("0.0", content)
            self.email_input.configure(text_color=C_TEXT)
            self.status_dot.configure(text="◉  FILE LOADED", text_color=C_AMBER)
        except Exception as e:
            messagebox.showerror("PhishGuard", f"Could not read file:\n{e}")

    # --------------------------------------------------------
    # CLEAR
    # --------------------------------------------------------
    def _clear_all(self):
        self.email_input.delete("0.0", "end")
        self.email_input.configure(text_color=C_TEXT3)
        self.email_input.insert("0.0", "Paste the suspicious email content here...")

        self.verdict_card.configure(fg_color=C_SURFACE, border_color=C_BORDER)
        self.risk_value.configure(text="PENDING", text_color=C_TEXT3)
        self.score_value.configure(text="— / 10",  text_color=C_TEXT3)
        self.action_label.configure(
            text="Awaiting specimen submission.", text_color=C_TEXT3
        )

        self.findings_count.configure(text="0 flags  ", text_color=C_TEXT3)
        self._write_findings(
            ["No analysis run yet.  Submit a specimen above."], idle=True
        )

        self.status_dot.configure(text="◉  READY", text_color=C_AMBER)
        self.last_result = None
        self.last_email  = ""

    # --------------------------------------------------------
    # EXPORT
    # --------------------------------------------------------
    def _export_txt(self):
        if not self.last_result:
            messagebox.showwarning("PhishGuard", "Run an analysis first.")
            return
        path = export_txt(self.last_result, self.last_email)
        if path:
            messagebox.showinfo("PhishGuard", f"Report saved:\n{path}")
        else:
            messagebox.showerror("PhishGuard", "Export failed.")

    def _export_csv(self):
        if not self.last_result:
            messagebox.showwarning("PhishGuard", "Run an analysis first.")
            return
        from datetime import datetime
        entry = {
            "session": 1,
            "time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk":    self.last_result.get("risk_level", ""),
            "score":   self.last_result.get("score", 0),
            "flags":   " | ".join(self.last_result.get("flags", {}).keys()),
            "preview": self.last_email[:80]
        }
        path = export_csv([entry])
        if path:
            messagebox.showinfo("PhishGuard", f"CSV saved:\n{path}")
        else:
            messagebox.showerror("PhishGuard", "CSV export failed.")


# -----------------------------------------------------------
# ENTRY POINT
# -----------------------------------------------------------
if __name__ == "__main__":
    app = PhishGuardApp()
    app.mainloop()