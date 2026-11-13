#!/usr/bin/env python3
"""Sync the UPG Lark public mailbox (Ida Sze) via IMAP and publish an
AES-GCM encrypted inbox snapshot (mail.enc.json) for the static viewer.

Secrets come only from the environment (GitHub Actions secrets):
  IMAP_HOST      default imap.feishu.cn (from the Lark admin page)
  IMAP_PORT      default 993
  IMAP_USER      default Ida.Sze@upg.com.hk
  IMAP_PASSWORD  the public mailbox IMAP/SMTP password (reset in Lark Admin)
  MAIL_VIEW_KEY  passphrase the viewer types in to decrypt the snapshot
  MAX_MESSAGES   default 100 (newest first, INBOX)
  MAX_SENT       default 20 (newest first, Sent folder, if found)
  MAX_FETCH_BYTES default 2000000 (messages bigger than this: headers only)

Nothing secret is printed. Only counts and folder names are logged.

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
import quopri
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


_ENCODED_WORD = re.compile(r"=\?([^?\s]+)\?([bBqQ])\?([^?]*)\?=")


def _decode_encoded_word(m):
    # Fallback for malformed encoded-words that email.decode_header leaves
    # untouched (e.g. a raw em-dash inside the payload, as some senders emit).
    charset, enc, text = m.group(1), m.group(2).lower(), m.group(3)
    try:
        if enc == "b":
            raw = base64.b64decode(text)
        else:
            raw = quopri.decodestring(text.replace("_", " ").encode("utf-8", errors="replace"))
        return raw.decode(charset, errors="replace")
    except Exception:
        return m.group(0)


def decode_str(raw):
    if raw is None:
        return ""
    if isinstance(raw, str):
        return _ENCODED_WORD.sub(_decode_encoded_word, raw)
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
    return _ENCODED_WORD.sub(_decode_encoded_word, "".join(out))


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


def thread_fields(msg):
    return {
        "message_id": (msg.get("Message-ID") or "").strip(),
        "in_reply_to": (msg.get("In-Reply-To") or "").strip(),
        "references": (msg.get("References") or "").strip(),
    }


def parse_msg(raw, uid, folder):
    msg = email.message_from_bytes(raw)
    try:
        dt = parsedate_to_datetime(msg.get("Date") or "")
        date_iso = dt.astimezone(timezone.utc).isoformat() if dt else ""
    except Exception:
        date_iso = ""
    text, attachments = body_text(msg)
    rec = {
        "uid": uid,
        "folder": folder,
        "date": date_iso,
        "from": decode_str(msg.get("From")),
        "to": decode_str(msg.get("To")),
        "subject": decode_str(msg.get("Subject")),
        "attachments": attachments,
        "body": text[:MAX_BODY],
    }
    rec.update(thread_fields(msg))
    return rec


def parse_header(raw, uid, folder, note=""):
    msg = email.message_from_bytes(raw)
    try:
        dt = parsedate_to_datetime(msg.get("Date") or "")
        date_iso = dt.astimezone(timezone.utc).isoformat() if dt else ""
    except Exception:
        date_iso = ""
    rec = {
        "uid": uid,
        "folder": folder,
        "date": date_iso,
        "from": decode_str(msg.get("From")),
        "to": decode_str(msg.get("To")),
        "subject": decode_str(msg.get("Subject")),
        "attachments": [],
        "body": note,
    }
    rec.update(thread_fields(msg))
    return rec


def connect(host, port, user, password, folder="INBOX"):
    mail = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
    try:
        mail.sock.settimeout(120)
    except Exception:
        pass
    mail.login(user, password)
    mail.select(folder)
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


def sync_folder(host, port, user, password, folder, max_messages, max_fetch):
    """Fetch the newest messages from one folder. Returns (records, skipped)."""
    mail = connect(host, port, user, password, folder)
    try:
        status, data = mail.search(None, "ALL")
        if status != "OK":
            print(f"[{folder}] IMAP search failed", file=sys.stderr)
            return [], 0
        uids = [u.decode("ascii") for u in data[0].split()]
        uids = uids[-max_messages:]

        # Size check first, in one small call, so a huge message never
        # gets a full fetch that kills the connection.
        sizes = {}
        if uids:
            try:
                status, data = mail.fetch(",".join(uids), "(UID RFC822.SIZE)")
                if status == "OK":
                    parts = []
                    for item in data:
                        if isinstance(item, tuple):
                            parts.append(item[0])
                        elif isinstance(item, bytes):
                            parts.append(item)
                    blob = b" ".join(parts).decode("ascii", errors="replace")
                    for m in re.finditer(r"UID (\d+) RFC822\.SIZE (\d+)", blob):
                        sizes[m.group(1)] = int(m.group(2))
            except Exception as e:
                print(f"[{folder}] size check failed, continuing without it: {e}")
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
                mail = connect(host, port, user, password, folder)
                if big:
                    raw = fetch_raw(mail, uid, "(BODY.PEEK[HEADER])")
                    record = parse_header(
                        raw, uid, folder, "（呢封信附件較大，未同步內文，請喺 Lark 睇原文。）"
                    )
                else:
                    raw = fetch_raw(mail, uid, "(RFC822)")
                    record = parse_msg(raw, uid, folder)
                break
            except Exception as e:
                print(f"[{folder}] uid {uid} attempt {attempt + 1} failed: {type(e).__name__}")
                record = None
                if attempt == 2:
                    # Last resort: header only, so the message still shows
                    # in the list instead of killing the sync.
                    try:
                        mail2 = connect(host, port, user, password, folder)
                        try:
                            raw = fetch_raw(mail2, uid, "(BODY.PEEK[HEADER])")
                            record = parse_header(
                                raw, uid, folder, "（呢封信同步時連線中斷，未同步內文。）"
                            )
                        finally:
                            close(mail2)
                    except Exception:
                        record = {
                            "uid": uid,
                            "folder": folder,
                            "date": "",
                            "from": "",
                            "to": "",
                            "subject": "（未能同步此封信）",
                            "attachments": [],
                            "body": "",
                            "message_id": "",
                            "in_reply_to": "",
                            "references": "",
                        }
            finally:
                if mail is not None:
                    close(mail)
        if record is None:
            skipped += 1
            continue
        messages.append(record)
    return messages, skipped


def find_sent_folder(host, port, user, password):
    """List folders (names only, logged) and return a Sent-like folder or None."""
    mail = None
    try:
        mail = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
        mail.login(user, password)
        status, data = mail.list()
        names = []
        if status == "OK" and data:
            for item in data:
                raw = item.decode("utf-8", errors="replace") if isinstance(item, bytes) else str(item)
                m = re.search(r'"([^"]+)"\s*$', raw.strip())
                names.append(m.group(1) if m else raw.strip())
        print("folders: " + ", ".join(names))
        for cand in ("Sent", "Sent Items", "INBOX.Sent", "Sent Messages"):
            if cand in names:
                return cand
        for n in names:
            low = n.lower()
            if "sent" in low or "已發" in low or "寄件" in low:
                return n
        return None
    except Exception as e:
        print(f"folder list failed: {type(e).__name__}")
        return None
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass


def main():
    host = os.environ.get("IMAP_HOST", "imap.feishu.cn")
    port = int(os.environ.get("IMAP_PORT", "993"))
    user = os.environ.get("IMAP_USER", "Ida.Sze@upg.com.hk")
    password = os.environ.get("IMAP_PASSWORD", "")
    view_key = os.environ.get("MAIL_VIEW_KEY", "")
    max_messages = int(os.environ.get("MAX_MESSAGES", "100"))
    max_sent = int(os.environ.get("MAX_SENT", "20"))
    max_fetch = int(os.environ.get("MAX_FETCH_BYTES", "2000000"))
    if not password or not view_key:
        print("IMAP_PASSWORD and MAIL_VIEW_KEY are required", file=sys.stderr)
        return 2

    inbox, skipped_inbox = sync_folder(host, port, user, password, "INBOX", max_messages, max_fetch)
    messages = inbox
    skipped = skipped_inbox

    sent_folder = find_sent_folder(host, port, user, password)
    if sent_folder:
        sent, skipped_sent = sync_folder(host, port, user, password, sent_folder, max_sent, max_fetch)
        messages = messages + sent
        skipped += skipped_sent
        print(f"synced Sent folder '{sent_folder}': {len(sent)} messages")
    else:
        print("no Sent folder found, skipping sent sync")

    # Newest first overall for the viewer list.
    messages.sort(key=lambda m: m.get("date") or "", reverse=True)

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
