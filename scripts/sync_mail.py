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

Speed notes: a run reuses the previous encrypted snapshot — messages whose
UID and size are unchanged are copied over without re-fetching, so a normal
run only fetches the few new mails. New small messages are fetched in one
batch call; if the server drops the connection mid-batch (``socket error:
EOF``, usually one very large message), it falls back to fetching them one
by one on fresh connections. Big messages are headers-only.

All IMAP commands use UID variants (UID SEARCH / UID FETCH) so message
identities stay stable even if a mail is deleted from the mailbox.
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


def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def derive_key(view_key, salt):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000
    )
    return kdf.derive(view_key.encode("utf-8"))


def load_previous_snapshot(view_key, path):
    """Decrypt the previous mail.enc.json (if any) for incremental reuse.
    Returns {(folder, uid): record} or {} on any failure."""
    try:
        with open(path, encoding="utf-8") as f:
            enc = json.load(f)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = derive_key(view_key, b64decode(enc["salt"]))
        plain = AESGCM(key).decrypt(b64decode(enc["nonce"]), b64decode(enc["data"]), None)
        payload = json.loads(plain.decode("utf-8"))
        out = {}
        for m in payload.get("messages") or []:
            out[(m.get("folder", "INBOX"), str(m.get("uid")))] = m
        return out
    except Exception as e:
        print(f"no usable previous snapshot ({type(e).__name__}), full fetch")
        return {}


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


def clean_html(html):
    """Strip active content from an HTML mail body before it is stored.
    The viewer renders it inside a sandboxed iframe (no scripts), but
    defence in depth: drop script/iframe/object/form tags, event-handler
    attributes and javascript: URLs here too."""
    html = re.sub(r"(?is)<(script|iframe|object|embed|form|link|meta|base|title)[^>]*>.*?</\1>", "", html)
    html = re.sub(r"(?is)<(script|iframe|object|embed|form|link|meta|base|title)[^>]*/?>", "", html)
    html = re.sub(r"(?is)\son\w+\s*=", " data-x=", html)
    html = re.sub(r"(?is)javascript\s*:", "", html)
    return html


def body_text(msg):
    """Prefer text/plain; fall back to stripped HTML.
    Also returns the cleaned raw HTML (for table layout) when present."""
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
        return "\n".join(text_parts).strip(), attachments, clean_html("\n".join(html_parts))
    if html_parts:
        html = "\n".join(html_parts)
        text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
        text = re.sub(r"(?is)<br\s*/?>", "\n", text)
        text = re.sub(r"(?is)</(p|div|tr|li|h\d)>", "\n", text)
        text = re.sub(r"(?is)<[^>]+>", "", text)
        import html as htmlmod

        return htmlmod.unescape(text).strip(), attachments, clean_html(html)
    return "", attachments, ""


def thread_fields(msg):
    return {
        "message_id": (msg.get("Message-ID") or "").strip(),
        "in_reply_to": (msg.get("In-Reply-To") or "").strip(),
        "references": (msg.get("References") or "").strip(),
    }


def parse_msg(raw, uid, folder, size):
    msg = email.message_from_bytes(raw)
    try:
        dt = parsedate_to_datetime(msg.get("Date") or "")
        date_iso = dt.astimezone(timezone.utc).isoformat() if dt else ""
    except Exception:
        date_iso = ""
    text, attachments, html = body_text(msg)
    rec = {
        "uid": uid,
        "folder": folder,
        "size": size,
        "date": date_iso,
        "from": decode_str(msg.get("From")),
        "to": decode_str(msg.get("To")),
        "subject": decode_str(msg.get("Subject")),
        "attachments": attachments,
        "body": text[:MAX_BODY],
        "body_html": html[:150000],
    }
    rec.update(thread_fields(msg))
    return rec


def parse_header(raw, uid, folder, size, note=""):
    msg = email.message_from_bytes(raw)
    try:
        dt = parsedate_to_datetime(msg.get("Date") or "")
        date_iso = dt.astimezone(timezone.utc).isoformat() if dt else ""
    except Exception:
        date_iso = ""
    rec = {
        "uid": uid,
        "folder": folder,
        "size": size,
        "date": date_iso,
        "from": decode_str(msg.get("From")),
        "to": decode_str(msg.get("To")),
        "subject": decode_str(msg.get("Subject")),
        "attachments": [],
        "body": note,
        "body_html": "",
    }
    rec.update(thread_fields(msg))
    return rec


def placeholder(uid, folder, size):
    return {
        "uid": uid,
        "folder": folder,
        "size": size,
        "date": "",
        "from": "",
        "to": "",
        "subject": "（未能同步此封信）",
        "attachments": [],
        "body": "",
        "body_html": "",
        "message_id": "",
        "in_reply_to": "",
        "references": "",
    }


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


def extract_uid(header):
    """UID of a message from a FETCH response header.

    UID FETCH replies look like ``12 FETCH (UID 1947 RFC822 {123}`` (the
    leading number is the sequence number, the UID is the ``UID`` attribute).
    Some servers instead put the UID up front, so fall back to that."""
    m = re.search(rb"UID (\d+)", header)
    if m:
        return m.group(1).decode("ascii")
    m = re.match(rb"(\d+) \(", header)
    if m:
        return m.group(1).decode("ascii")
    return None


def parse_batch_fetch(data, chunk):
    """Parse one UID FETCH response into {uid: raw_bytes}.

    Returns None if the UIDs do not line up exactly with the chunk that
    was requested (then the caller falls back to one-by-one fetching)."""
    got = {}
    for item in data:
        if isinstance(item, tuple) and isinstance(item[1], bytes):
            uid = extract_uid(item[0])
            if uid is not None:
                got[uid] = item[1]
    if set(got.keys()) != set(chunk):
        return None
    return got


def uid_fetch_raw(mail, uid, what):
    status, data = mail.uid("fetch", uid, what)
    if status != "OK" or not data:
        raise imaplib.IMAP4.error(f"fetch {what} failed for {uid}")
    for item in data:
        if isinstance(item, tuple) and isinstance(item[1], bytes):
            return item[1]
    raise imaplib.IMAP4.error(f"fetch {what} returned no bytes for {uid}")


def fetch_one(host, port, user, password, folder, uid, size, max_fetch):
    """Fetch a single message on a fresh connection, with retries.
    Returns a record; never raises for one bad message."""
    big = size > max_fetch
    for attempt in range(3):
        mail = None
        try:
            mail = connect(host, port, user, password, folder)
            if big:
                raw = uid_fetch_raw(mail, uid, "(BODY.PEEK[HEADER])")
                return parse_header(
                    raw, uid, folder, size, "（呢封信附件較大，未同步內文，請喺 Lark 睇原文。）"
                )
            raw = uid_fetch_raw(mail, uid, "(RFC822)")
            return parse_msg(raw, uid, folder, size)
        except Exception as e:
            print(f"[{folder}] uid {uid} attempt {attempt + 1} failed: {type(e).__name__}")
            if attempt == 2:
                try:
                    mail2 = connect(host, port, user, password, folder)
                    try:
                        raw = uid_fetch_raw(mail2, uid, "(BODY.PEEK[HEADER])")
                        return parse_header(
                            raw, uid, folder, size, "（呢封信同步時連線中斷，未同步內文。）"
                        )
                    finally:
                        close(mail2)
                except Exception:
                    return placeholder(uid, folder, size)
        finally:
            if mail is not None:
                close(mail)
    return placeholder(uid, folder, size)


def sync_folder(host, port, user, password, folder, max_messages, max_fetch, prev):
    """Fetch the newest messages from one folder.
    Unchanged messages are reused from the previous snapshot."""
    mail = connect(host, port, user, password, folder)
    try:
        status, data = mail.uid("search", None, "ALL")
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
                status, data = mail.uid("fetch", ",".join(uids), "(UID RFC822.SIZE)")
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
    to_fetch = []
    for uid in reversed(uids):  # newest first
        size = sizes.get(uid, 0)
        old = prev.get((folder, uid))
        if old is not None and old.get("size", -1) == size and size > 0:
            messages.append(old)
        elif size > max_fetch:
            messages.append(fetch_one(host, port, user, password, folder, uid, size, max_fetch))
        else:
            to_fetch.append((uid, size))

    # Fetch new messages in small batches (10 per call) over one shared
    # connection. A single 100-message fetch gets cut off by the server
    # (socket EOF), and fetching one-by-one with a fresh login each time
    # takes minutes; 10-at-a-time is the middle ground. A failed chunk
    # falls back to one-by-one for that chunk only.
    if to_fetch:
        size_map = dict(to_fetch)
        chunk_size = 10
        try:
            mail = connect(host, port, user, password, folder)
        except Exception as e:
            print(f"[{folder}] connect failed ({type(e).__name__}), fetching one-by-one")
            mail = None
        if mail is None:
            for uid, size in to_fetch:
                messages.append(fetch_one(host, port, user, password, folder, uid, size, max_fetch))
        else:
            try:
                i = 0
                while i < len(to_fetch):
                    chunk = [uid for uid, _ in to_fetch[i:i + chunk_size]]
                    got = None
                    try:
                        status, data = mail.uid("fetch", ",".join(chunk), "(RFC822)")
                        if status == "OK" and data:
                            got = parse_batch_fetch(data, chunk)
                            if got is None:
                                print(f"[{folder}] chunk fetch UID mismatch, falling back")
                    except Exception as e:
                        print(f"[{folder}] chunk fetch failed ({type(e).__name__}), falling back")
                        got = None
                        close(mail)
                        mail = None
                    if got is not None:
                        for uid in chunk:
                            messages.append(parse_msg(got[uid], uid, folder, size_map[uid]))
                    else:
                        for uid in chunk:
                            messages.append(fetch_one(host, port, user, password, folder, uid, size_map[uid], max_fetch))
                    i += chunk_size
                    if mail is None and i < len(to_fetch):
                        try:
                            mail = connect(host, port, user, password, folder)
                        except Exception as e:
                            print(f"[{folder}] reconnect failed ({type(e).__name__}), remaining one-by-one")
                            for uid, size in to_fetch[i:]:
                                messages.append(fetch_one(host, port, user, password, folder, uid, size, max_fetch))
                            break
            finally:
                if mail is not None:
                    close(mail)

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

    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mail.enc.json")
    prev = load_previous_snapshot(view_key, out_path)

    inbox, skipped_inbox = sync_folder(host, port, user, password, "INBOX", max_messages, max_fetch, prev)
    messages = inbox
    skipped = skipped_inbox

    sent_folder = find_sent_folder(host, port, user, password)
    if sent_folder:
        sent, skipped_sent = sync_folder(host, port, user, password, sent_folder, max_sent, max_fetch, prev)
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
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(view_key, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    out = {
        "v": 1,
        "kdf": "pbkdf2-sha256-200k",
        "salt": b64(salt),
        "nonce": b64(nonce),
        "data": b64(ciphertext),
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f)
    print(f"synced {len(messages)} messages ({skipped} skipped) -> mail.enc.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
