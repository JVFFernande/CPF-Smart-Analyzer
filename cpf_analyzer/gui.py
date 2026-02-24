from __future__ import annotations

import json
import re
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from cpf_analyzer.report import analyze
from cpf_analyzer.core import generate_fake_cpf
from cpf_analyzer.batch import load_inputs, run_batch, write_json, write_csv


PALETTE = {
    "bg": "#F6F3EE",
    "card": "#FFFFFF",
    "chip_bg": "#F2ECE4",
    "text": "#1F1E1C",
    "muted": "#6B645B",
    "accent": "#E88F3A",
    "accent_hover": "#D57E2F",
    "soft": "#FBE7D3",
    "soft_hover": "#F7D9BE",
    "low_bg": "#E6F4EA",
    "low_fg": "#1E7F4B",
    "med_bg": "#FFF4E5",
    "med_fg": "#9A5B00",
    "high_bg": "#FDECEA",
    "high_fg": "#B3261E",
}


def only_digits(v: str) -> str:
    return re.sub(r"\D+", "", v or "")


def mask_cpf_live(d: str) -> str:
    d = only_digits(d)[:11]
    if len(d) <= 3:
        return d
    if len(d) <= 6:
        return f"{d[:3]}.{d[3:]}"
    if len(d) <= 9:
        return f"{d[:3]}.{d[3:6]}.{d[6:]}"
    return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:11]}"


class CozyStyle:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.style = ttk.Style(root)
        self._apply()

    def _apply(self) -> None:
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.root.configure(bg=PALETTE["bg"])

        self.style.configure(".", background=PALETTE["bg"], foreground=PALETTE["text"])
        self.style.configure("TFrame", background=PALETTE["bg"])
        self.style.configure("Card.TFrame", background=PALETTE["card"])
        self.style.configure("TLabel", font=("Segoe UI", 10), background=PALETTE["bg"], foreground=PALETTE["text"])
        self.style.configure("Muted.TLabel", background=PALETTE["bg"], foreground=PALETTE["muted"])
        self.style.configure("Card.TLabel", background=PALETTE["card"], foreground=PALETTE["text"])
        self.style.configure("CardMuted.TLabel", background=PALETTE["card"], foreground=PALETTE["muted"])
        self.style.configure("Chip.TLabel", background=PALETTE["chip_bg"], foreground=PALETTE["text"])

        self.style.configure(
            "Accent.TButton",
            padding=(14, 9),
            background=PALETTE["accent"],
            foreground="white",
            borderwidth=0,
            focusthickness=0,
        )
        self.style.map("Accent.TButton", background=[("active", PALETTE["accent_hover"])])

        self.style.configure(
            "Soft.TButton",
            padding=(14, 9),
            background=PALETTE["soft"],
            foreground=PALETTE["text"],
            borderwidth=0,
            focusthickness=0,
        )
        self.style.map("Soft.TButton", background=[("active", PALETTE["soft_hover"])])

        self.style.configure("TEntry", padding=(10, 8))
        self.style.configure("TNotebook", background=PALETTE["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab", padding=(14, 8))

        self.style.configure(
            "Treeview",
            background=PALETTE["card"],
            fieldbackground=PALETTE["card"],
            foreground=PALETTE["text"],
            rowheight=28,
            borderwidth=0,
        )
        self.style.configure(
            "Treeview.Heading",
            background=PALETTE["chip_bg"],
            foreground=PALETTE["text"],
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        self.style.map("Treeview", background=[("selected", "#F4D6BA")])

        self.root.option_add("*Text.background", PALETTE["card"])
        self.root.option_add("*Text.foreground", PALETTE["text"])
        self.root.option_add("*Text.insertBackground", PALETTE["text"])
        self.root.option_add("*Listbox.background", PALETTE["card"])
        self.root.option_add("*Listbox.foreground", PALETTE["text"])
        self.root.option_add("*Listbox.selectBackground", "#F4D6BA")
        self.root.option_add("*Listbox.selectForeground", PALETTE["text"])


class Card(ttk.Frame):
    def __init__(self, parent: tk.Widget, padding: int = 14) -> None:
        super().__init__(parent, style="Card.TFrame", padding=padding)


class App(ttk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=16)
        self.master = master
        self._payload_batch: dict | None = None
        self._last_masked_value = ""

        self.master.title("CPF Smart Analyzer — simulado")
        self.master.geometry("1040x700")
        self.master.minsize(980, 640)

        self._build_ui()
        self.master.bind("<Return>", lambda _e: self.on_analyze())

    def _build_ui(self) -> None:
        self.pack(fill="both", expand=True)

        header = ttk.Frame(self)
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(header, text="CPF Smart Analyzer", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(
            header,
            text="Validação + heurísticas + score de risco (simulado) • com modo Lote",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.tab_single = ttk.Frame(nb, padding=12)
        self.tab_batch = ttk.Frame(nb, padding=12)

        nb.add(self.tab_single, text="Análise única")
        nb.add(self.tab_batch, text="Lote")

        self._build_single(self.tab_single)
        self._build_batch(self.tab_batch)

        footer = ttk.Frame(self)
        footer.pack(fill="x", pady=(10, 0))
        ttk.Label(
            footer,
            text="⚠️ Projeto de portfólio (simulado). Não use para validação de identidade real.",
            style="Muted.TLabel",
        ).pack(anchor="w")

    # ---------- SINGLE ----------
    def _build_single(self, parent: ttk.Frame) -> None:
        top = Card(parent, padding=16)
        top.pack(fill="x", pady=(0, 12))

        row = ttk.Frame(top, style="Card.TFrame")
        row.pack(fill="x")

        ttk.Label(row, text="CPF", style="CardMuted.TLabel").pack(side="left")

        self.cpf_var = tk.StringVar()
        self.entry = ttk.Entry(row, textvariable=self.cpf_var, width=40)
        self.entry.pack(side="left", padx=10)
        self.entry.focus()
        self.entry.bind("<KeyRelease>", self.on_type)

        ttk.Button(row, text="Analisar", style="Accent.TButton", command=self.on_analyze).pack(side="left", padx=6)
        ttk.Button(row, text="Gerar fictício", style="Soft.TButton", command=self.on_generate).pack(side="left", padx=6)
        ttk.Button(row, text="Limpar", command=self.on_clear).pack(side="left", padx=6)

        summary = Card(parent, padding=16)
        summary.pack(fill="x", pady=(0, 12))

        top_line = ttk.Frame(summary, style="Card.TFrame")
        top_line.pack(fill="x")

        self.lbl_valid = ttk.Label(top_line, text="Válido: —", style="Card.TLabel", font=("Segoe UI", 11, "bold"))
        self.lbl_valid.pack(side="left")

        self.lbl_risk = ttk.Label(top_line, text="Risco: —", style="Chip.TLabel", padding=(10, 4))
        self.lbl_risk.pack(side="left", padx=12)

        self.lbl_formatted = ttk.Label(summary, text="Formatado: —", style="CardMuted.TLabel")
        self.lbl_formatted.pack(anchor="w", pady=(10, 0))

        self.lbl_masked = ttk.Label(summary, text="Mascarado: —", style="CardMuted.TLabel")
        self.lbl_masked.pack(anchor="w", pady=(6, 0))

        self.lbl_reason = ttk.Label(summary, text="Motivo: —", style="CardMuted.TLabel", wraplength=900)
        self.lbl_reason.pack(anchor="w", pady=(6, 0))

        mid = ttk.Frame(parent)
        mid.pack(fill="both", expand=True)

        left = ttk.Frame(mid)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))

        right = ttk.Frame(mid)
        right.pack(side="right", fill="both", expand=True)

        flags_frame = Card(left, padding=16)
        flags_frame.pack(fill="both", expand=True, pady=(0, 12))

        ttk.Label(flags_frame, text="Flags / sinais", style="CardMuted.TLabel").pack(anchor="w")
        self.flags_list = tk.Listbox(flags_frame, height=9, bd=0, highlightthickness=0)
        self.flags_list.pack(fill="both", expand=True, pady=(8, 0))

        json_frame = Card(right, padding=16)
        json_frame.pack(fill="both", expand=True)

        header_json = ttk.Frame(json_frame, style="Card.TFrame")
        header_json.pack(fill="x")
        ttk.Label(header_json, text="Relatório (JSON)", style="CardMuted.TLabel").pack(side="left")

        ttk.Button(header_json, text="Copiar", command=self.on_copy_json).pack(side="right")
        ttk.Button(header_json, text="Salvar…", command=self.on_save_json).pack(side="right", padx=8)

        self.text = tk.Text(json_frame, wrap="word", bd=0, highlightthickness=0)
        self.text.pack(fill="both", expand=True, pady=(10, 0))

    def on_type(self, _e=None) -> None:
        raw = only_digits(self.cpf_var.get())[:11]
        masked = mask_cpf_live(raw)

        if masked != self._last_masked_value:
            self.cpf_var.set(masked)
            self.entry.icursor(len(masked))
            self._last_masked_value = masked

        if len(raw) == 11:
            self._render_report(analyze(masked))
        else:
            self._reset_view(keep_input=True)

    def on_analyze(self) -> None:
        cpf = self.cpf_var.get().strip()
        if not cpf:
            messagebox.showwarning("Atenção", "Digite um CPF.")
            return
        self._render_report(analyze(cpf))

    def _render_report(self, rep: dict) -> None:
        a = rep["analysis"]

        self.lbl_valid.config(text=f"Válido: {'SIM ✅' if a['is_valid'] else 'NÃO ❌'}")
        self.lbl_formatted.config(text=f"Formatado: {a['formatted']}")
        self.lbl_masked.config(text=f"Mascarado: {a['masked']}")
        self.lbl_reason.config(text=f"Motivo: {a['reason'] or '—'}")

        level = rep["risk_level"]
        score = rep["risk_score"]

        if level == "low":
            self.lbl_risk.config(text=f"LOW • {score}/100", background=PALETTE["low_bg"], foreground=PALETTE["low_fg"])
        elif level == "medium":
            self.lbl_risk.config(text=f"MEDIUM • {score}/100", background=PALETTE["med_bg"], foreground=PALETTE["med_fg"])
        else:
            self.lbl_risk.config(text=f"HIGH • {score}/100", background=PALETTE["high_bg"], foreground=PALETTE["high_fg"])

        self.flags_list.delete(0, tk.END)
        if rep["flags"]:
            for f in rep["flags"]:
                self.flags_list.insert(tk.END, f"[{f['severity']}] {f['code']}: {f['message']}")
        else:
            self.flags_list.insert(tk.END, "Nenhuma flag.")

        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, json.dumps(rep, ensure_ascii=False, indent=2))

    def _reset_view(self, keep_input: bool = False) -> None:
        if not keep_input:
            self.cpf_var.set("")
            self._last_masked_value = ""

        self.lbl_valid.config(text="Válido: —")
        self.lbl_risk.config(text="Risco: —", background=PALETTE["chip_bg"], foreground=PALETTE["text"])
        self.lbl_formatted.config(text="Formatado: —")
        self.lbl_masked.config(text="Mascarado: —")
        self.lbl_reason.config(text="Motivo: —")
        self.flags_list.delete(0, tk.END)
        self.text.delete("1.0", tk.END)

    def on_generate(self) -> None:
        cpf = generate_fake_cpf(formatted=True)
        self.cpf_var.set(cpf)
        self._last_masked_value = cpf
        self._render_report(analyze(cpf))

    def on_clear(self) -> None:
        self._reset_view(keep_input=False)
        self.entry.focus()

    def on_copy_json(self) -> None:
        data = self.text.get("1.0", tk.END).strip()
        if not data:
            return
        self.master.clipboard_clear()
        self.master.clipboard_append(data)
        messagebox.showinfo("OK", "JSON copiado.")

    def on_save_json(self) -> None:
        data = self.text.get("1.0", tk.END).strip()
        if not data:
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Todos", "*.*")],
            initialfile="relatorio_cpf.json",
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write(data)

        messagebox.showinfo("OK", "Relatório salvo.")

    # ---------- BATCH ----------
    def _build_batch(self, parent: ttk.Frame) -> None:
        top = Card(parent, padding=16)
        top.pack(fill="x", pady=(0, 12))

        row = ttk.Frame(top, style="Card.TFrame")
        row.pack(fill="x")

        ttk.Button(row, text="Carregar TXT/CSV…", style="Accent.TButton", command=self.on_batch_load).pack(side="left")

        ttk.Label(row, text="Coluna CSV:", style="CardMuted.TLabel").pack(side="left", padx=(12, 6))
        self.csv_col_var = tk.StringVar(value="cpf")
        ttk.Entry(row, textvariable=self.csv_col_var, width=18).pack(side="left")

        ttk.Button(row, text="Exportar JSON…", style="Soft.TButton", command=self.on_batch_export_json).pack(
            side="left", padx=8
        )
        ttk.Button(row, text="Exportar CSV…", command=self.on_batch_export_csv).pack(side="left")
        ttk.Button(row, text="Limpar", command=self.on_batch_clear).pack(side="left", padx=8)

        info = Card(parent, padding=16)
        info.pack(fill="x", pady=(0, 12))
        self.lbl_batch_info = ttk.Label(info, text="Nenhum arquivo carregado.", style="CardMuted.TLabel")
        self.lbl_batch_info.pack(anchor="w")

        table = Card(parent, padding=10)
        table.pack(fill="both", expand=True)

        cols = ("input", "valid", "risk", "score", "reason")
        self.tree = ttk.Treeview(table, columns=cols, show="headings")
        self.tree.heading("input", text="Entrada")
        self.tree.heading("valid", text="Válido")
        self.tree.heading("risk", text="Risco")
        self.tree.heading("score", text="Score")
        self.tree.heading("reason", text="Motivo")

        self.tree.column("input", width=240)
        self.tree.column("valid", width=70, anchor="center")
        self.tree.column("risk", width=90, anchor="center")
        self.tree.column("score", width=70, anchor="center")
        self.tree.column("reason", width=520)

        vsb = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)
        vsb.pack(side="right", fill="y", pady=6)

    def on_batch_load(self) -> None:
        path = filedialog.askopenfilename(
            title="Selecione um arquivo",
            filetypes=[("TXT", "*.txt"), ("CSV", "*.csv"), ("Todos", "*.*")],
        )
        if not path:
            return

        try:
            values = load_inputs(path, column=self.csv_col_var.get().strip() or "cpf")
            payload = run_batch(values)
        except Exception as e:
            messagebox.showerror("Erro", str(e))
            return

        self._payload_batch = payload
        self._render_batch(payload)

    def _render_batch(self, payload: dict) -> None:
        for i in self.tree.get_children():
            self.tree.delete(i)

        s = payload["summary"]
        self.lbl_batch_info.config(
            text=(
                f"Total: {s['total']} • Válidos: {s['valid']} • Inválidos: {s['invalid']} • "
                f"Risco low/medium/high: {s['risk_low']}/{s['risk_medium']}/{s['risk_high']}"
            )
        )

        for item in payload["items"]:
            a = item["analysis"]
            valid_txt = "SIM" if a["is_valid"] else "NÃO"
            self.tree.insert(
                "",
                tk.END,
                values=(a["raw_input"], valid_txt, item["risk_level"], item["risk_score"], a["reason"] or ""),
            )

    def on_batch_export_json(self) -> None:
        if not self._payload_batch:
            messagebox.showinfo("Info", "Carregue um lote primeiro.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Todos", "*.*")],
            initialfile="batch_report.json",
        )
        if not path:
            return

        write_json(path, self._payload_batch, pretty=True)
        messagebox.showinfo("OK", "JSON exportado.")

    def on_batch_export_csv(self) -> None:
        if not self._payload_batch:
            messagebox.showinfo("Info", "Carregue um lote primeiro.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Todos", "*.*")],
            initialfile="batch_report.csv",
        )
        if not path:
            return

        write_csv(path, self._payload_batch["items"])
        messagebox.showinfo("OK", "CSV exportado.")

    def on_batch_clear(self) -> None:
        self._payload_batch = None
        self.lbl_batch_info.config(text="Nenhum arquivo carregado.")
        for i in self.tree.get_children():
            self.tree.delete(i)


def main() -> None:
    root = tk.Tk()
    CozyStyle(root)
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()