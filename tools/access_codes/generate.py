#!/usr/bin/env python3
"""
Standalone login code/token generator.

Generates:
- Tool token: base64url payload + HMAC signature (payload.signature).
- Quick codes: BAS/ADV/PRE/ADM style strings for each role.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import tkinter as tk
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Dict, List


PROFILE_MAP = {
    "viewer": "basic",
    "auditor": "advanced",
    "editor": "premium",
    "owner": "admin",
}

STATE_FILE = Path(__file__).with_suffix(".state.json")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(payload: str, secret: str) -> str:
    mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return _b64url(mac)


def build_payload(profile: str, ref: str | None, minutes: int, *, now: datetime | None = None) -> dict:
    """Construct the token payload so multiple entry points stay in sync."""
    role = PROFILE_MAP.get(profile.lower(), profile.lower())
    now = now or datetime.now(timezone.utc)
    payload = {
        "exp": (now + timedelta(minutes=minutes)).isoformat(),
        "iat": now.isoformat(),
        "nonce": secrets.token_urlsafe(8),
        "profile": profile,
        "role": role,
    }
    if ref:
        payload["ref"] = ref
    return payload


def generate_token(profile: str, ref: str | None, minutes: int, secret: str) -> str:
    payload = build_payload(profile, ref, minutes)
    payload_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_b64 = _b64url(payload_str.encode())
    sig = _sign(payload_str, secret)
    return f"{payload_b64}.{sig}"


def generate_quick_codes() -> Dict[str, str]:
    return {
        "basic": f"BAS-{secrets.randbelow(900000) + 100000}",
        "advanced": f"ADV-{secrets.randbelow(900000) + 100000}",
        "premium": f"PRE-{secrets.randbelow(900000) + 100000}",
        "admin": f"ADM-{secrets.randbelow(900000) + 100000}",
    }


def load_saved_entries() -> List[dict]:
    if not STATE_FILE.exists():
        return []
    try:
        with STATE_FILE.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []

    entries: List[dict] = []
    for item in raw:
        try:
            expires_at = datetime.fromisoformat(item["expires_at"])
        except (KeyError, ValueError):
            continue

        entries.append(
            {
                "id": item.get("id") or secrets.token_hex(6),
                "kind": item.get("kind", "token"),
                "label": item.get("label", "Generated"),
                "value": item.get("value", ""),
                "expires_at": expires_at,
            }
        )
    return entries


def save_entries(entries: List[dict]) -> None:
    payload = []
    for entry in entries:
        payload.append(
            {
                "id": entry["id"],
                "kind": entry["kind"],
                "label": entry["label"],
                "value": entry["value"],
                "expires_at": entry["expires_at"].isoformat(),
            }
        )
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def format_remaining(seconds: float) -> str:
    if seconds <= 0:
        return "expired"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if parts:
        parts.append(f"{sec:02d}s")
    else:
        parts.append(f"{sec}s")
    return " ".join(parts)


class AccessCodeApp:
    def __init__(self, defaults: dict | None = None):
        self.defaults = defaults or {}
        self.entries: dict[str, dict] = {}

        self.root = tk.Tk()
        self.root.title("Access Code Generator")
        self.root.geometry("980x520")

        self._build_form()
        self._build_table()
        self._load_existing()
        self._update_countdown()

    def _build_form(self) -> None:
        form = ttk.Frame(self.root, padding=10)
        form.pack(fill="x")

        # Profile field
        ttk.Label(form, text="Profile").grid(row=0, column=0, sticky="w")
        self.profile_var = tk.StringVar(value=self.defaults.get("profile", "auditor"))
        profile_input = ttk.Combobox(form, textvariable=self.profile_var, values=list(PROFILE_MAP.keys()))
        profile_input.grid(row=1, column=0, sticky="we", padx=(0, 10))

        # Reference field
        ttk.Label(form, text="Reference (optional)").grid(row=0, column=1, sticky="w")
        self.ref_var = tk.StringVar(value=self.defaults.get("ref") or "")
        ttk.Entry(form, textvariable=self.ref_var).grid(row=1, column=1, sticky="we", padx=(0, 10))

        # Minutes field
        ttk.Label(form, text="Validity (minutes)").grid(row=0, column=2, sticky="w")
        self.minutes_var = tk.IntVar(value=int(self.defaults.get("minutes", 60)))
        ttk.Spinbox(form, from_=1, to=24 * 60, textvariable=self.minutes_var, width=8).grid(row=1, column=2, sticky="w", padx=(0, 10))

        # Secret field
        ttk.Label(form, text="Secret").grid(row=0, column=3, sticky="w")
        self.secret_var = tk.StringVar(value=self.defaults.get("secret") or os.environ.get("LOGIN_TOKEN_SECRET", "gdpr-dpia-secret"))
        ttk.Entry(form, textvariable=self.secret_var, width=28).grid(row=1, column=3, sticky="we", padx=(0, 10))

        # Options
        self.token_var = tk.BooleanVar(value=True)
        self.quick_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(form, text="Generate token", variable=self.token_var).grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Checkbutton(form, text="Generate quick codes", variable=self.quick_var).grid(row=2, column=1, sticky="w", pady=(8, 0))

        # Buttons
        button_frame = ttk.Frame(form)
        button_frame.grid(row=2, column=3, sticky="e")
        ttk.Button(button_frame, text="Generate", command=self._generate).pack(side="left", padx=(0, 6))
        ttk.Button(button_frame, text="Clear expired", command=self._clear_expired).pack(side="left")

        for i in range(4):
            form.columnconfigure(i, weight=1)

    def _build_table(self) -> None:
        container = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        container.pack(fill="both", expand=True)

        columns = ("label", "value", "expires", "remaining")
        self.tree = ttk.Treeview(container, columns=columns, show="headings", height=14)
        self.tree.heading("label", text="Item")
        self.tree.heading("value", text="Password / Code")
        self.tree.heading("expires", text="Expires at")
        self.tree.heading("remaining", text="Remaining")

        self.tree.column("label", width=160, anchor="w")
        self.tree.column("value", width=360, anchor="w")
        self.tree.column("expires", width=200, anchor="w")
        self.tree.column("remaining", width=120, anchor="center")

        scrollbar_y = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=scrollbar_y.set, xscroll=scrollbar_x.set)

        self.tree.tag_configure("expired", foreground="red")

        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")

        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        button_frame = ttk.Frame(container)
        button_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(button_frame, text="Copy selected", command=self._copy_selected).pack(side="left")

    def _load_existing(self) -> None:
        for entry in load_saved_entries():
            self.entries[entry["id"]] = entry
            self._upsert_tree(entry)

    def _upsert_tree(self, entry: dict) -> None:
        expires_label = entry["expires_at"].astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        remaining = (entry["expires_at"] - datetime.now(timezone.utc)).total_seconds()
        remaining_label = format_remaining(remaining)

        tags = ("expired",) if remaining <= 0 else ()
        if self.tree.exists(entry["id"]):
            self.tree.item(entry["id"], values=(entry["label"], entry["value"], expires_label, remaining_label), tags=tags)
        else:
            self.tree.insert("", "end", iid=entry["id"], values=(entry["label"], entry["value"], expires_label, remaining_label), tags=tags)

    def _generate(self) -> None:
        minutes = self.minutes_var.get()
        if minutes <= 0:
            messagebox.showerror("Invalid duration", "Minutes must be greater than zero.")
            return

        profile = self.profile_var.get().strip() or "auditor"
        ref = self.ref_var.get().strip() or None
        secret = self.secret_var.get()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        new_entries: List[dict] = []

        if self.token_var.get():
            token = generate_token(profile, ref, minutes, secret)
            new_entries.append(
                {
                    "id": secrets.token_hex(6),
                    "kind": "token",
                    "label": f"Token ({profile})",
                    "value": token,
                    "expires_at": expires_at,
                }
            )

        if self.quick_var.get():
            quick_codes = generate_quick_codes()
            for role, code in quick_codes.items():
                new_entries.append(
                    {
                        "id": secrets.token_hex(6),
                        "kind": f"quick-{role}",
                        "label": f"Quick ({role})",
                        "value": code,
                        "expires_at": expires_at,
                    }
                )

        if not new_entries:
            messagebox.showinfo("Nothing generated", "Enable at least one option to generate.")
            return

        for entry in new_entries:
            self.entries[entry["id"]] = entry
            self._upsert_tree(entry)

        save_entries(list(self.entries.values()))
        messagebox.showinfo("Generated", f"Created {len(new_entries)} item(s).")

    def _clear_expired(self) -> None:
        to_remove = [item_id for item_id, entry in self.entries.items() if (entry["expires_at"] - datetime.now(timezone.utc)).total_seconds() <= 0]
        if not to_remove:
            messagebox.showinfo("No expired items", "There are no expired entries to remove.")
            return
        for item_id in to_remove:
            self.entries.pop(item_id, None)
            if self.tree.exists(item_id):
                self.tree.delete(item_id)
        save_entries(list(self.entries.values()))

    def _copy_selected(self) -> None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select a row to copy.")
            return
        entry = self.entries.get(selection[0])
        if not entry:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(entry["value"])
        messagebox.showinfo("Copied", "Password/code copied to clipboard.")

    def _update_countdown(self) -> None:
        for entry in self.entries.values():
            self._upsert_tree(entry)
        self.root.after(1000, self._update_countdown)

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate login tokens or quick codes.")
    parser.add_argument("--profile", default="auditor", help="viewer|auditor|editor|owner (maps to basic/advanced/premium/admin)")
    parser.add_argument("--ref", help="Reference code to embed (optional)")
    parser.add_argument("--minutes", type=int, default=60, help="Token validity in minutes (default 60)")
    parser.add_argument("--only-quick", action="store_true", help="Only output quick codes, skip token")
    parser.add_argument("--secret", default=os.environ.get("LOGIN_TOKEN_SECRET", "gdpr-dpia-secret"), help="Signing secret (default gdpr-dpia-secret)")
    parser.add_argument("--ui", action="store_true", help="Launch the graphical generator with persistence")
    args = parser.parse_args()

    if args.ui:
        defaults = {"profile": args.profile, "ref": args.ref, "minutes": args.minutes, "secret": args.secret}
        app = AccessCodeApp(defaults=defaults)
        app.run()
        return

    if not args.only_quick:
        token = generate_token(args.profile, args.ref, args.minutes, args.secret)
        print("Token:")
        print(token)
        print()

    codes = generate_quick_codes()
    print("Quick codes:")
    for role, code in codes.items():
        print(f"  {role}: {code}")


if __name__ == "__main__":
    main()
