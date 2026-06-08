# 目付 Metsuke - Repo Interview Guard

在 GitHub / GitLab / Bitbucket 開啟原始碼檔案時即時分析,當檔案出現 DPRK 假面試惡意戰役(Contagious Interview / DeceptiveDevelopment)特徵時警示。**僅警示,不修改、不阻擋頁面。**

- 規格(範圍鎖定版):[docs/SPEC.md](docs/SPEC.md)
- 設計風格指南:[docs/design.md](docs/design.md) · mockup:[docs/design-mockup.html](docs/design-mockup.html)

## 結構

| 檔案 | 職責 |
|---|---|
| `manifest.json` | MV3;僅 `storage` 權限 + 具名 host permissions |
| `detector.js` | 純偵測引擎(無 DOM / 無網路);RIG-001~014 規則與門檻常數 |
| `content.js` | URL 解析、取文字(raw → GitHub embedded JSON)、idle 分析、Shadow DOM 橫幅、reveal、SPA 換頁偵測 |
| `background.js` | service worker:代理 raw fetch(帶 cookie)、設定 badge |
| `popup.html/css/js` | 判決摘要、信任清單(allowlist)、總開關 |
| `tests/run.js` | 規則正向 fixture + 誤報語料(0 high 誤報門檻) |

## 開發

```sh
# 跑偵測引擎測試(門檻常數調整必附;SPEC §10)
node tests/run.js
```

載入擴充功能:`chrome://extensions` → 開發人員模式 → 「載入未封裝項目」→ 選本目錄。

## 兩種分析模式

- **檔案頁**(`/blob`、`/-/blob`、`/src`):開檔時即時分析單檔(v1 主線)。
- **repo 首頁 / tree 頁**:定點掃描固定的高價值入口檔(`package.json`、`.vscode/tasks.json`、`.vscode/settings.json`、`.claude/settings*.json`、`.cursorrules`、`.github/copilot-instructions.md`、`CLAUDE.md`、`AGENTS.md`、`GEMINI.md`),不必逐一點開檔案。findings 標注來源檔並可點擊前往(v1.1,SPEC §12)。

## 偵測規則(enabled,共 16 條)

RIG-001 右緣外隱藏程式碼 · RIG-002 空白填充推出畫面 · RIG-003 切段+交換 base64 C2 · RIG-004 C2 埠 1224/1244 · RIG-005 base64 解碼出 IP:port · RIG-006 eval/Function loader · RIG-007 atob→eval 鏈 · RIG-008 錢包/金鑰路徑 · RIG-009 瀏覽器 profile 目錄(med)· RIG-010 安裝腳本下載/內嵌執行 · RIG-011 安裝腳本連 IP · RIG-013 VS Code 開啟即執行 · RIG-016 Claude Code hooks 開啟即執行 · RIG-017 AI 指令檔隱藏注入字元 · **RIG-018 husky git hook 開啟即執行** · **RIG-019 SSH authorized_keys 後門**

Experimental(預設關閉,轉 enabled 須走 SPEC §10):RIG-012(依賴非 registry 來源)、RIG-014(右緣外高熵字串)。

完整的**規則 ↔ 情資對照、風險/信心/家族、組合規則與 2026 情資來源**見 **[docs/rules.md](docs/rules.md)**。

## 告警分級(降誤報)

每條規則帶 **severity(風險)× confidence(誤報可能性)× family(家族)**,由 `detector.assess()` 計算呈現:

- **alarm - 完整珊瑚紅框**:高信心強訊號(已知 C2 埠、錢包路徑、隱形注入字元…),或 **≥2 個不同家族組合**(多階段攻擊鏈)。
- **caution - 較小琥珀框**:單一易誤報訊號(合法 postinstall 也可能 `curl`)或僅中風險,語氣收斂、不干擾。

第一個危險信號就立即彈出 banner;尚未掃完時顯示 loading,掃完再更新。

## 隱私

不蒐集、不傳輸、不販售;內容僅本機分析。唯一網路請求為向使用者當前同站取該檔 raw 原始碼。設定僅存 `{ enabled, allowlist }` 於 `chrome.storage.sync`。
