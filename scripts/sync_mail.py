#!/usr/bin/env python3
"""Sync the UPG Lark public mailbox (Ida Sze) via IMAP and publish an
AES-GCM encrypted inbox snapshot (mail.enc.json) for the static viewer.

Secrets come only from the environment (GitHub Actions secrets):
  IMAP_HOST      default imap.feishu.cn (from the Lark admin page)
  IMAP_PORT      default 993
  IMAP_USER      default Ida.Sze@upg.com.hk
  IMAP_PASSWORD  the public mailbox IMAP/SMTP password (reset in Lark Admin)
  MAIL_VIEW_KEY  passphrase the viewer types in to decrypt the snapshot
  MAX_MESSAGES   default 100 (newest first)

Nothing secret is printed. Only a count is logged.
"""
import base64
import email
import json
import os
import re
import ssl
import sys
from datetime import datetime, timezone
from email.header import decode_header
from email.utils import parsedate_to_datetime

import imaplib

MAX_BODY = 20000


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def decode_str(raw):
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        parts = decode_header(raw)
    except Exception:
        return str(raw)
    out = []
    for text, charset in parts:
        if isinstance(text, bytes):
            try:
                out.append(text.decode(charset or "utf-8", errors="replace"))
            except Exception:
                out.append(text.decode("utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out)


def body_text(msg):
    """Prefer text/plain; fall back to stripped HTML."""
    text_parts = []
    html_parts = []
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                attachments.append(decode_str(part.get_filename()) or "attachment")
                continue
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = payload.decode("utf-8", errors="replace")
            if ctype == "text/plain":
                text_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(text)
    else:
        try:
            payload = msg.get_payload(decode=True)
        except Exception:
            payload = None
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html_parts.append(text)
            else:
                text_parts.append(text)
    if text_parts:
        return "\n".join(text_parts).strip(), attachments
    if html_parts:
        html = "\n".join(html_parts)
        html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
        html = re.sub(r"(?is)<br\s*/?>", "\n", html)
        html = re.sub(r"(?is)</(p|div|tr|li|h\d)>", "\n", html)
        html = re.sub(r"(?is)<[^>]+>", "", html)
        import html as htmlmod

        return htmlmod.unescape(html).strip(), attachments
    return "", attachments


def main():
    host = os.environ.get("IMAP_HOST", "imap.feishu.cn")
    port = int(os.environ.get("IMAP_PORT", "993"))
    user = os.environ.get("IMAP_USER", "Ida.Sze@upg.com.hk")
    password = os.environ.get("IMAP_PASSWORD", "")
    view_key = os.environ.get("MAIL_VIEW_KEY", "")
    max_messages = int(os.environ.get("MAX_MESSAGES", "100"))
    if not password or not view_key:
        print("IMAP_PASSWORD and MAIL_VIEW_KEY are required", file=sys.stderr)
        return 2

    mail = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
    try:
        mail.login(user, password)
        mail.select("INBOX")
        status, data = mail.search(None, "ALL")
        if status != "OK":
            print("IMAP search failed", file=sys.stderr)
            return 1
        uids = data[0].split()
        uids = uids[-max_messages:]
        messages = []
        for uid in reversed(uids):  # newest first
            status, data = mail.fetch(uid, "(RFC822)")
            if status != "OK" or not data or not data[0]:
                continue
            raw = data[0][1]
            if isinstance(raw, tuple):
                raw = raw[1]
            msg = email.message_from_bytes(raw)
            try:
                dt = parsedate_to_datetime(msg.get("Date") or "")
                date_iso = dt.astimezone(timezone.utc).isoformat() if dt else ""
            except Exception:
                date_iso = ""
            text, attachments = body_text(msg)
            messages.append(
                {
                    "uid": uid.decode("ascii", errors="replace"),
                    "date": date_iso,
                    "from": decode_str(msg.get("From")),
                    "to": decode_str(msg.get("To")),
                    "subject": decode_str(msg.get("Subject")),
                    "attachments": attachments,
                    "body": text[:MAX_BODY],
                }
            )
    finally:
        try:
            mail.logout()
        except Exception:
            pass

    payload = {
        "mailbox": user,
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "count": len(messages),
        "messages": messages,
    }
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    # AES-GCM, key from PBKDF2-HMAC-SHA256(passphrase, salt, 200k).
    # WebCrypto on the viewer side derives the identical key.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000
    )
    key = kdf.derive(view_key.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    out = {
        "v": 1,
        "kdf": "pbkdf2-sha256-200k",
        "salt": b64(salt),
        "nonce": b64(nonce),
        "data": b64(ciphertext),
    }
    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mail.enc.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f)
    print(f"synced {len(messages)} messages -> mail.enc.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
