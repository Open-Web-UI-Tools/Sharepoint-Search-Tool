# SharePoint Search — Open WebUI Tool

Search SharePoint files, pages, and list items directly from [Open WebUI](https://github.com/open-webui/open-webui) using the Microsoft Graph Search API with **delegated (per-user) authentication**.

Each user connects their own Microsoft account, so results are always scoped to what that user is actually allowed to see — the tool never holds a shared service credential.

## Features

- 🔎 Full-text search across SharePoint files, pages, and list items via Microsoft Graph
- 👤 Delegated per-user OAuth (device-code flow) — results respect each user's permissions
- 🔐 Access/refresh tokens stored **encrypted at rest** (Fernet) when an encryption key is set
- 📄 On-the-fly text extraction from PDF, DOCX, PPTX, and XLSX attachments
- 🧩 Parent/child chunking + BM25 ranking so only the most relevant passages reach the LLM
- 🎯 Optional scoping to specific SharePoint site IDs

## Requirements

```
PyPDF2, python-docx, python-pptx, openpyxl
```

(`cryptography` is also required for encrypted token storage.)

## Installation

1. In Open WebUI, go to **Workspace → Tools → +** (Create new tool).
2. Paste the contents of [`sharepoint_search.py`](sharepoint_search.py) and save.
3. Configure the **Valves** (see below).

## Configuration (Valves)

| Valve | Default | Description |
|-------|---------|-------------|
| `azure_client_id` | _(empty)_ | Azure AD app (client) ID for the registered application |
| `azure_tenant_id` | `common` | Azure AD tenant ID, or `common` for multi-tenant |
| `encryption_key` | _(empty)_ | Secret key for encrypting stored tokens. Set any random string (e.g. a UUID). If empty, tokens are stored in plaintext. |
| `sharepoint_site_ids` | _(empty)_ | Semicolon-separated SharePoint site IDs to scope search. Leave empty to search all sites the user can access. |
| `max_results` | `10` | Max search hits to return |
| `max_content_chars` | `50000` | Max characters of extracted content |
| `max_download_mb` | `50` | Max attachment size to download for extraction |

### Azure AD app registration

1. Register an application in **Azure Portal → App registrations**.
2. Under **Authentication**, enable **Allow public client flows** (required for the device-code flow).
3. Add the delegated Microsoft Graph permissions your search needs (e.g. `Files.Read.All`, `Sites.Read.All`), then grant consent.
4. Copy the **Application (client) ID** into the `azure_client_id` valve and set `azure_tenant_id`.

## Authentication flow

On first use the tool returns a device-code prompt. Visit the URL, enter the code, and sign in with your Microsoft account. Tokens are cached (encrypted if `encryption_key` is set) and refreshed automatically.

## License

[MIT](LICENSE)
