from __future__ import annotations
import json
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox
from tkinter.scrolledtext import ScrolledText as TkScrolledText  # robust across Tk builds

from plugins.base import AppContext

# ===================== Persistence =====================

def _state_path() -> Path:
    base = Path.home() / ".rct"
    base.mkdir(parents=True, exist_ok=True)
    return base / "weekly_dates.json"

def _load_state() -> Dict:
    p = _state_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def _save_state(data: Dict) -> None:
    try:
        _state_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

# ===================== Dates / Bank Holidays =====================

DOW_ABBR = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]

def _easter_sunday(year: int) -> date:
    """Gregorian Easter (Meeus/Jones/Butcher)."""
    a = year % 19
    b = year // 100
    c = year % 100
    d = b // 4
    e = b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19*a + b - d - g + 15) % 30
    i = c // 4
    k = c % 4
    l = (32 + 2*e + 2*i - h - k) % 7
    m = (a + 11*h + 22*l) // 451
    month = (h + l - 7*m + 114) // 31
    day = ((h + l - 7*m + 114) % 31) + 1
    return date(year, month, day)

def _next_monday(d: date) -> date:
    return d + timedelta(days=(7 - d.weekday()) % 7)

def _first_monday(year: int, month: int) -> date:
    d = date(year, month, 1)
    return d if d.weekday() == 0 else _next_monday(d)

def _last_monday(year: int, month: int) -> date:
    if month == 12:
        d = date(year+1, 1, 1) - timedelta(days=1)
    else:
        d = date(year, month+1, 1) - timedelta(days=1)
    while d.weekday() != 0:
        d -= timedelta(days=1)
    return d

def _observe_fixed(d: date) -> date:
    if d.weekday() == 5:  # Sat
        return d + timedelta(days=2)
    if d.weekday() == 6:  # Sun
        return d + timedelta(days=1)
    return d

def _christmas_and_boxing(year: int) -> List[Tuple[date, str]]:
    cd = date(year, 12, 25)
    bd = date(year, 12, 26)
    obs_cd = _observe_fixed(cd)
    obs_bd = _observe_fixed(bd)
    if obs_cd == obs_bd:
        obs_bd = obs_bd + timedelta(days=1)
    holidays = []
    if obs_cd != cd:
        holidays.append((obs_cd, "Christmas Day (Substitute day)"))
    else:
        holidays.append((cd, "Christmas Day"))
    if obs_bd != bd:
        holidays.append((obs_bd, "Boxing Day (Substitute day)"))
    else:
        holidays.append((bd, "Boxing Day"))
    return holidays

def _scotland_new_years(year: int) -> List[Tuple[date, str]]:
    d1 = date(year, 1, 1)
    d2 = date(year, 1, 2)
    o1 = _observe_fixed(d1)
    o2 = _observe_fixed(d2)
    if o2 == o1:
        o2 = o2 + timedelta(days=1)
    days = []
    days.append((o1 if o1 != d1 else d1, "New Year’s Day" + (" (Substitute day)" if o1 != d1 else "")))
    days.append((o2 if o2 != d2 else d2, "2 January" + (" (Substitute day)" if o2 != d2 else "")))
    return days

def _engw_new_years(year: int) -> List[Tuple[date, str]]:
    d1 = date(year, 1, 1)
    o1 = _observe_fixed(d1)
    return [(o1 if o1 != d1 else d1, "New Year’s Day" + (" (Substitute day)" if o1 != d1 else ""))]

def bank_holidays_uk(year: int, region: str) -> Dict[date, str]:
    hol: Dict[date, str] = {}
    easter = _easter_sunday(year)
    good_fri = easter - timedelta(days=2)
    easter_mon = easter + timedelta(days=1)

    if region == "England & Wales":
        for d, n in _engw_new_years(year): hol[d] = n
        hol[good_fri] = "Good Friday"
        hol[easter_mon] = "Easter Monday"
        hol[_first_monday(year, 5)] = "Early May bank holiday"
        hol[_last_monday(year, 5)] = "Spring bank holiday"
        hol[_last_monday(year, 8)] = "Summer bank holiday"
        for d, n in _christmas_and_boxing(year): hol[d] = n

    elif region == "Scotland":
        for d, n in _scotland_new_years(year): hol[d] = n
        hol[good_fri] = "Good Friday"
        hol[_first_monday(year, 5)] = "Early May bank holiday"
        hol[_last_monday(year, 5)] = "Spring bank holiday"
        hol[_first_monday(year, 8)] = "Summer bank holiday"
        d = date(year, 11, 30); o = _observe_fixed(d)
        hol[o if o != d else d] = "St Andrew’s Day" + (" (Substitute day)" if o != d else "")
        for d, n in _christmas_and_boxing(year): hol[d] = n

    else:  # Northern Ireland
        for d, n in _engw_new_years(year): hol[d] = n
        d = date(year, 3, 17); o = _observe_fixed(d)
        hol[o if o != d else d] = "St Patrick’s Day" + (" (Substitute day)" if o != d else "")
        hol[good_fri] = "Good Friday"
        hol[easter_mon] = "Easter Monday"
        hol[_first_monday(year, 5)] = "Early May bank holiday"
        hol[_last_monday(year, 5)] = "Spring bank holiday"
        d = date(year, 7, 12); o = _observe_fixed(d)
        hol[o if o != d else d] = "Battle of the Boyne (Orangemen’s Day)" + (" (Substitute day)" if o != d else "")
        hol[_last_monday(year, 8)] = "Summer bank holiday"
        for d, n in _christmas_and_boxing(year): hol[d] = n

    return hol

# ===================== Plugin =====================

class WeeklyDatesTool:
    key = "weekly_dates"
    title = "Weekly Dates (UK)"
    description = "Generate dates for X weeks (daily Mon–Sun or weekly) with UK bank holiday comments. Presets supported."

    def __init__(self):
        self.ctx: Optional[AppContext] = None
        self._ui_mode = "standard"

        # UI vars
        self.weeks_var: Optional[tb.IntVar] = None
        self.start_var: Optional[tb.StringVar] = None  # YYYY-MM-DD
        self.include_today_var: Optional[tb.BooleanVar] = None
        self.region_var: Optional[tb.StringVar] = None
        self.format_var: Optional[tb.StringVar] = None  # Pro-only
        self.freq_var: Optional[tb.StringVar] = None    # Daily / Weekly

        # Presets
        self._state: Dict = {}
        self.preset_var: Optional[tb.StringVar] = None
        self.preset_combo = None

        # Widgets
        self.output = None
        self.pro_frame = None
        self.log = None

        self.panel = None

    # ---------- UI ----------
    def make_panel(self, master, context: AppContext):
        self.ctx = context
        self._ui_mode = context.ui_mode
        self._state = _load_state()

        root = tb.Frame(master)

        # Presets
        pr = tb.Frame(root); pr.pack(fill="x", padx=8, pady=(8,6))
        tb.Label(pr, text="Preset:").pack(side="left")
        self.preset_var = tb.StringVar(value=self._initial_preset_value())
        self.preset_combo = tb.Combobox(pr, textvariable=self.preset_var, state="readonly", width=28)
        self._refresh_preset_combo()
        self.preset_combo.pack(side="left", padx=6)
        self.preset_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_preset_from_combo())
        tb.Button(pr, text="Save as…", command=self._save_as_preset, bootstyle="secondary").pack(side="left", padx=4)
        tb.Button(pr, text="Delete", command=self._delete_preset, bootstyle="warning").pack(side="left", padx=4)

        # Options
        basic = tb.Labelframe(root, text="Options")
        basic.pack(fill="x", padx=8, pady=(0,8))

        r1 = tb.Frame(basic); r1.pack(fill="x", padx=8, pady=6)
        self.weeks_var = tb.IntVar(value=12)
        tb.Label(r1, text="Weeks:").pack(side="left")
        tb.Spinbox(r1, from_=1, to=520, increment=1, textvariable=self.weeks_var, width=6).pack(side="left", padx=6)

        self.start_var = tb.StringVar(value=str(date.today()))
        tb.Label(r1, text="Start (YYYY-MM-DD):").pack(side="left", padx=(12,4))
        tb.Entry(r1, textvariable=self.start_var, width=12).pack(side="left")

        self.include_today_var = tb.BooleanVar(value=True)
        tb.Checkbutton(r1, text="Include start date", variable=self.include_today_var).pack(side="left", padx=12)

        r2 = tb.Frame(basic); r2.pack(fill="x", padx=8, pady=6)
        self.region_var = tb.StringVar(value="England & Wales")
        tb.Label(r2, text="Region:").pack(side="left")
        tb.Combobox(r2, textvariable=self.region_var, state="readonly",
                    values=["England & Wales","Scotland","Northern Ireland"], width=20).pack(side="left", padx=6)

        # Frequency selector
        r3 = tb.Frame(basic); r3.pack(fill="x", padx=8, pady=6)
        self.freq_var = tb.StringVar(value="Daily (Mon–Sun)")  # default to ALL days
        tb.Label(r3, text="Frequency:").pack(side="left")
        tb.Combobox(r3, textvariable=self.freq_var, state="readonly",
                    values=["Daily (Mon–Sun)", "Weekly"], width=20).pack(side="left", padx=6)

        # Pro-only format string
        self.format_var = tb.StringVar(value="{d}/{m}/{yy} {dow} - {holiday}")
        fmt_row = tb.Frame(basic); fmt_row.pack(fill="x", padx=8, pady=6)
        tb.Label(fmt_row, text="Format (Pro):").pack(side="left")
        tb.Entry(fmt_row, textvariable=self.format_var).pack(side="left", fill="x", expand=True, padx=6)
        if self._ui_mode != "pro":
            fmt_row.pack_forget()

        # Actions
        actions = tb.Frame(root); actions.pack(fill="x", padx=8, pady=(0,8))
        tb.Button(actions, text="Generate", command=self._generate, bootstyle="success").pack(side="left", padx=4)
        tb.Button(actions, text="Copy to clipboard", command=self._copy, bootstyle="secondary").pack(side="left", padx=4)
        tb.Button(actions, text="Clear", command=self._clear, bootstyle="warning").pack(side="left", padx=4)

        # Output box
        out_frame = tb.Labelframe(root, text="Output")
        out_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.output = TkScrolledText(out_frame, height=18, wrap="word")
        self.output.pack(fill="both", expand=True, padx=8, pady=8)

        # Pro log
        self.pro_frame = tb.Labelframe(root, text="Log (Pro)")
        self.log = tb.ScrolledText(self.pro_frame, height=6)
        if self._ui_mode == "pro":
            self.pro_frame.pack(fill="both", expand=False, padx=8, pady=(0,8))
            self.log.pack(fill="both", expand=True, padx=8, pady=6)

        # Load last used
        self._apply_last_used()

        self.panel = root
        return root

    def start(self, context: AppContext, targets: List[Path], argv: List[str]):
        pass

    def cleanup(self):
        self._persist_last_used()

    def on_mode_changed(self, ui_mode: str):
        self._ui_mode = ui_mode
        if ui_mode == "pro":
            if not self.pro_frame.winfo_ismapped():
                self.pro_frame.pack(fill="both", expand=False, padx=8, pady=(0,8))
                self.log.pack(fill="both", expand=True, padx=8, pady=6)
        else:
            if self.pro_frame.winfo_ismapped():
                self.pro_frame.pack_forget()

    # ---------- Presets ----------
    def _initial_preset_value(self) -> str:
        st = _load_state()
        names = [p.get("name") for p in st.get("presets", []) if "name" in p]
        return "(last used)" if st.get("last") else (names[0] if names else "(none)")

    def _refresh_preset_combo(self):
        st = _load_state()
        names = ["(last used)"] + [p.get("name","") for p in st.get("presets", [])]
        self.preset_combo.configure(values=names)

    def _apply_preset_from_combo(self):
        name = self.preset_var.get().strip()
        if name == "(last used)":
            self._apply_last_used(); return
        st = _load_state()
        for p in st.get("presets", []):
            if p.get("name") == name:
                self._apply_snapshot(p); return

    def _save_as_preset(self):
        prompt = tb.Toplevel(master=self.panel)
        prompt.title("Save Preset"); prompt.geometry("340x180")
        frm = tb.Frame(prompt, padding=10); frm.pack(fill="both", expand=True)
        tb.Label(frm, text="Preset name:").pack(anchor="w")
        name_var = tb.StringVar()
        tb.Entry(frm, textvariable=name_var).pack(fill="x", pady=6)
        btns = tb.Frame(frm); btns.pack(fill="x", pady=(6,0))
        def ok():
            name = name_var.get().strip()
            if not name:
                Messagebox.show_warning("Enter a name."); return
            st = _load_state()
            snap = self._snapshot(); snap["name"] = name
            arr = st.get("presets", [])
            for i, p in enumerate(arr):
                if p.get("name") == name:
                    arr[i] = snap; break
            else:
                arr.append(snap)
            st["presets"] = arr
            _save_state(st)
            self._refresh_preset_combo()
            self.preset_var.set(name)
            prompt.destroy()
        tb.Button(btns, text="Save", command=ok, bootstyle="success").pack(side="right", padx=6)
        tb.Button(btns, text="Cancel", command=prompt.destroy, bootstyle="secondary").pack(side="right")

    def _delete_preset(self):
        name = self.preset_var.get().strip()
        if name in ("(last used)", "(none)", ""):
            Messagebox.show_info("Select a saved preset to delete."); return
        st = _load_state()
        arr = [p for p in st.get("presets", []) if p.get("name") != name]
        st["presets"] = arr
        _save_state(st)
        self._refresh_preset_combo()
        self.preset_var.set("(last used)" if st.get("last") else "(none)")

    def _snapshot(self) -> Dict:
        return {
            "weeks": int(self.weeks_var.get() or 1),
            "start": self.start_var.get().strip(),
            "include_start": bool(self.include_today_var.get()),
            "region": self.region_var.get().strip(),
            "format": self.format_var.get().strip(),
            "frequency": self.freq_var.get().strip(),
        }

    def _apply_snapshot(self, snap: Dict):
        self.weeks_var.set(int(snap.get("weeks", 12)))
        self.start_var.set(snap.get("start", str(date.today())))
        self.include_today_var.set(bool(snap.get("include_start", True)))
        if snap.get("region") in ("England & Wales","Scotland","Northern Ireland"):
            self.region_var.set(snap.get("region"))
        if snap.get("format"):
            self.format_var.set(snap.get("format"))
        if snap.get("frequency") in ("Daily (Mon–Sun)","Weekly"):
            self.freq_var.set(snap.get("frequency"))

    def _apply_last_used(self):
        st = _load_state()
        last = st.get("last")
        if last:
            self._apply_snapshot(last)

    def _persist_last_used(self):
        st = _load_state()
        st["last"] = self._snapshot()
        _save_state(st)

    # ---------- Generate / Copy ----------
    def _parse_start(self) -> Optional[date]:
        s = self.start_var.get().strip()
        try:
            y, m, d = [int(x) for x in s.split("-")]
            return date(y, m, d)
        except Exception:
            Messagebox.show_warning("Start date must be YYYY-MM-DD.")
            return None

    def _generate(self):
        start = self._parse_start()
        if not start: return
        weeks = int(self.weeks_var.get() or 1)
        include = bool(self.include_today_var.get())
        region = self.region_var.get().strip()
        default_fmt = "{d}/{m}/{yy} {dow} - {holiday}"
        fmt_used = (self.format_var.get().strip() or default_fmt) if self._ui_mode == "pro" else default_fmt
        freq = self.freq_var.get().strip()

        # Determine cadence
        if freq.startswith("Daily"):
            step_days = 1
            count = weeks * 7
            first_day = start if include else (start + timedelta(days=1))
        else:  # Weekly
            step_days = 7
            count = weeks
            first_day = start if include else (start + timedelta(days=7))

        if count <= 0:
            Messagebox.show_warning("Weeks must be >= 1.")
            return

        # Compute bank holidays for the span
        last_day = first_day + timedelta(days=(count - 1) * step_days)
        years = set()
        cur = first_day
        while cur <= last_day:
            years.add(cur.year)
            cur += timedelta(days=max(1, step_days))
        hol: Dict[date, str] = {}
        for y in sorted(years):
            hol.update(bank_holidays_uk(y, region))

        # Build lines (+ blank line between Sunday and Monday)
        self.output.delete("1.0", "end")
        lines: List[str] = []
        for i in range(count):
            d = first_day + timedelta(days=i * step_days)
            holiday = hol.get(d, "").strip()
            tokens = {
                "d": str(d.day),
                "dd": f"{d.day:02d}",
                "m": str(d.month),
                "mm": f"{d.month:02d}",
                "yy": f"{d.year % 100:02d}",
                "yyyy": str(d.year),
                "dow": DOW_ABBR[d.weekday()],
                "holiday": holiday,
            }
            out = fmt_used
            for k, v in tokens.items():
                out = out.replace("{" + k + "}", v)
            if "{holiday}" not in fmt_used and " - " not in out:
                out = out + (" - " + holiday if holiday else " -")
            lines.append(out if holiday else out.replace("{holiday}", "").rstrip())

            # ⬇️ This is the only behavioral change:
            if freq.startswith("Daily"):
                # Insert spacer *after* Sundays, so Monday is visually separated
                if d.weekday() == 6 and (i + 1) != count:
                    lines.append("")
            else:
                # Weekly mode: blank line between entries
                if (i + 1) != count:
                    lines.append("")

        text = "\n".join(lines) + ("\n" if lines else "")
        self.output.insert("end", text)
        if self._ui_mode == "pro":
            try:
                self.log.insert("end",
                                f"[GENERATE] {len([l for l in lines if l.strip()])} dates ({freq}) from {first_day} ({region})\n")
                self.log.see("end")
            except Exception:
                pass
        self._persist_last_used()

    def _copy(self):
        try:
            txt = self.output.get("1.0", "end").rstrip("\n")
            if not txt.strip():
                Messagebox.show_info("Nothing to copy yet. Click Generate first.")
                return
            self.output.clipboard_clear()
            self.output.clipboard_append(txt)
            Messagebox.show_info("Copied to clipboard.")
        except Exception as e:
            Messagebox.show_error(message=str(e), title="Copy failed")

    def _clear(self):
        try:
            self.output.delete("1.0","end")
            if self._ui_mode == "pro" and self.log:
                self.log.delete("1.0","end")
        except Exception:
            pass

PLUGIN = WeeklyDatesTool()