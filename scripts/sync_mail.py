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
  MAX_FETCH_BYTES default 2000000 (messages bigger than this: headers only)

Nothing secret is printed. Only a count is logged.

Resilience notes: the Feishu IMAP server sometimes closes the connection
mid-fetch (``socket error: EOF``), usually on a very large message. So we
check RFC822.SIZE first, fetch big messages as headers-only, and retry
each normal fetch on a fresh connection instead of letting one bad
message abort the whole sync.
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


def parse_msg(raw, uid):
    msg = email.message_from_bytes(raw)
    try:
        dt = parsedate_to_datetime(msg.get("Date") or "")
        date_iso = dt.astimezone(timezone.utc).isoformat() if dt else ""
    except Exception:
        date_iso = ""
    text, attachments = body_text(msg)
    return {
        "uid": uid,
        "date": date_iso,
        "from": decode_str(msg.get("From")),
        "to": decode_str(msg.get("To")),
        "subject": decode_str(msg.get("Subject")),
        "attachments": attachments,
        "body": text[:MAX_BODY],
    }


def parse_header(raw, uid, note=""):
    msg = email.message_from_bytes(raw)
    try:
        dt = parsedate_to_datetime(msg.get("Date") or "")
        date_iso = dt.astimezone(timezone.utc).isoformat() if dt else ""
    except Exception:
        date_iso = ""
    return {
        "uid": uid,
        "date": date_iso,
        "from": decode_str(msg.get("From")),
        "to": decode_str(msg.get("To")),
        "subject": decode_str(msg.get("Subject")),
        "attachments": [],
        "body": note,
    }


def connect(host, port, user, password):
    mail = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
    try:
        mail.sock.settimeout(120)
    except Exception:
        pass
    mail.login(user, password)
    mail.select("INBOX")
    return mail


def close(mail):
    try:
        mail.close()
    except Exception:
        pass
    try:
        mail.logout()
    except Exception:
        pass


def fetch_raw(mail, uid, what):
    status, data = mail.fetch(uid, what)
    if status != "OK" or not data:
        raise imaplib.IMAP4.error(f"fetch {what} failed for {uid}")
    for item in data:
        if isinstance(item, tuple) and isinstance(item[1], bytes):
            return item[1]
    raise imaplib.IMAP4.error(f"fetch {what} returned no bytes for {uid}")


def main():
    host = os.environ.get("IMAP_HOST", "imap.feishu.cn")
    port = int(os.environ.get("IMAP_PORT", "993"))
    user = os.environ.get("IMAP_USER", "Ida.Sze@upg.com.hk")
    password = os.environ.get("IMAP_PASSWORD", "")
    view_key = os.environ.get("MAIL_VIEW_KEY", "")
    max_messages = int(os.environ.get("MAX_MESSAGES", "100"))
    max_fetch = int(os.environ.get("MAX_FETCH_BYTES", "2000000"))
    if not password or not view_key:
        print("IMAP_PASSWORD and MAIL_VIEW_KEY are required", file=sys.stderr)
        return 2

    mail = connect(host, port, user, password)
    try:
        status, data = mail.search(None, "ALL")
        if status != "OK":
            print("IMAP search failed", file=sys.stderr)
            return 1
        uids = [u.decode("ascii") for u in data[0].split()]
        uids = uids[-max_messages:]

        # Size check first, in one small call, so a huge message never
        # gets a full fetch that kills the connection.
        sizes = {}
        if uids:
            try:
                status, data = mail.fetch(",".join(uids), "(UID RFC822.SIZE)")
                if status == "OK":
                    blob = b" ".join(
                        item[0] if isinstance(item, tuple) else b""
                        for item in data
                        if item
                    ).decode("ascii", errors="replace")
                    for m in re.finditer(r"UID (\d+) RFC822\.SIZE (\d+)", blob):
                        sizes[m.group(1)] = int(m.group(2))
            except Exception as e:
                print(f"size check failed, continuing without it: {e}")
    finally:
        close(mail)

    messages = []
    skipped = 0
    for uid in reversed(uids):  # newest first
        size = sizes.get(uid, 0)
        big = size > max_fetch
        record = None
        # Fresh connection per message: if the server drops us mid-fetch,
        # only this message is affected, never the whole sync.
        for attempt in range(3):
            mail = None
            try:
                mail = connect(host, port, user, password)
                if big:
                    raw = fetch_raw(mail, uid, "(BODY.PEEK[HEADER])")
                    record = parse_header(
                        raw, uid, "（呢封信附件較大，未同步內文，請喺 Lark 睇原文。）"
                    )
                else:
                    raw = fetch_raw(mail, uid, "(RFC822)")
                    record = parse_msg(raw, uid)
                break
            except Exception as e:
                print(f"uid {uid} attempt {attempt + 1} failed: {type(e).__name__}")
                record = None
                if attempt == 2:
                    # Last resort: header only, so the message still shows
                    # in the list instead of killing the sync.
                    try:
                        mail2 = connect(host, port, user, password)
                        try:
                            raw = fetch_raw(mail2, uid, "(BODY.PEEK[HEADER])")
                            record = parse_header(
                                raw, uid, "（呢封信同步時連線中斷，未同步內文。）"
                            )
                        finally:
                            close(mail2)
                    except Exception:
                        record = {
                            "uid": uid,
                            "date": "",
                            "from": "",
                            "to": "",
                            "subject": "（未能同步此封信）",
                            "attachments": [],
                            "body": "",
                        }
            finally:
                if mail is not None:
                    close(mail)
        if record is None:
            skipped += 1
            continue
        messages.append(record)

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
    print(f"synced {len(messages)} messages ({skipped} skipped) -> mail.enc.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
