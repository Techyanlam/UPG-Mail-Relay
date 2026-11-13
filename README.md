# UPG 公共郵箱中轉（Ida Sze）

唯讀網頁中轉，等唔係公共郵箱成員嘅同事都可以睇 Ida.Sze@upg.com.hk 嘅信，
唔使再喺 Outlook 搞 IMAP。

## 點運作

- GitHub Actions 每 15 分鐘用 IMAP 讀一次收件匣（最新 100 封，只讀內文，唔刪信）。
- 讀到嘅信即時用 AES-GCM 加密，寫入 `mail.enc.json`（公開放喺 Pages 都睇唔到內容）。
- `index.html` 係靜態閱覽頁：入閱覽密碼先會喺瀏覽器入面解密，密碼唔會傳送去任何地方。
- 附件唔會同步，只會列出附件名（v1）。

## 設定步驟（Yan 做）

1. **Reset IMAP 密碼**：Lark 管理後台 → 郵箱 → 地址管理 → 公共郵箱 → Ida Sze → 編輯 →
   IMAP/SMTP 密碼 → 重置。**唔好再用截圖入面嗰個舊密碼，佢已經露出咗。**
2. **開 repo**：喺 GitHub 開一個新 repo（例如 `UPG-Mail-Relay`），將呢度啲檔案推上去，
   並將個 repo 加返入 Muse 嘅 GitHub App 授權範圍（Muse 暫時開唔到新 repo，403）。
   注意：GitHub App 推唔到 `.github/workflows/*.yml`，個 workflow 檔要用網頁編輯器直接加返。
3. **加兩個 Secret**（repo → Settings → Secrets and variables → Actions）：
   - `IMAP_PASSWORD`：上面第 1 步 reset 完嘅新密碼
   - `MAIL_VIEW_KEY`：你自己揀嘅閱覽密碼（睇信嗰個人要入呢個；揀個夠長嘅）
4. **開 GitHub Pages**：repo → Settings → Pages → Deploy from a branch → `main` / `/ (root)`。
   網址會係 `https://techyanlam.github.io/UPG-Mail-Relay/`。
5. **手動跑一次**：Actions → Sync UPG public mailbox → Run workflow，睇下有冇成功寫入 `mail.enc.json`。
6. 將 Pages 連結 + 閱覽密碼話返俾睇信嗰個人。

## 檔案

- `index.html` — 閱覽頁（PBKDF2 200k + AES-GCM 解密）
- `scripts/sync_mail.py` — IMAP 同步 + 加密
- `.github/workflows/sync.yml` — 每 15 分鐘同步一次
- `mail.enc.json` — 加密後嘅信件快照（由 workflow 自動產生，唔好人手改）
