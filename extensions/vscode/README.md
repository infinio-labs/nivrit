# Nivrit for VS Code

Browse, copy, and inject secrets from your Nivrit workspace directly inside VS Code.

## Features

- PAT + password sign-in (client-side decryption via Rust/WASM).
- Tree view: Organizations → Projects → Environments → Secrets.
- Copy a single secret value to the clipboard.
- Copy all secrets for an environment as a `.env` block.
- Insert an environment's secrets into an existing `.env` file.

## Configuration

| Setting | Default | Description |
| ------- | ------- | ----------- |
| `nivrit.apiUrl` | `http://localhost:4000` | Base URL of the Nivrit API server. |

## Commands

- `Nivrit: Sign In`
- `Nivrit: Sign Out`
- `Nivrit: Refresh`
- `Nivrit: Copy Secret to Clipboard`
- `Nivrit: View Secret`
- `Nivrit: Copy All as .env`
- `Nivrit: Insert into .env File`
