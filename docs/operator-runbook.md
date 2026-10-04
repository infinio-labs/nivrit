# Nivrit operator runbook

This is the shortest supported path for running Nivrit for a real project. The
public MVP supports the web UI, API, CLI, and Node.js SDK. It is pre-audit; do
not use it as the only control for high-value production secrets.

## 1. Prepare the host

Use a host with Docker or Podman, persistent storage, and a TLS reverse proxy.
The bundled web container listens on loopback port `8080`; do not expose the
API port directly.

```bash
cp .env.example .env
openssl rand -hex 32                 # set NIVRIT_AUTH_SECRET
openssl rand -base64 32              # set NIVRIT_TOTP_ENCRYPTION_KEY
openssl rand -base64 32              # set NIVRIT_SIGNING_KEY_SEED
```

Replace every placeholder in `.env`. Keep the file outside version control and
set its permissions to `0600`. Set `NIVRIT_DEPLOY_CORS_ORIGIN` to the exact
public HTTPS origin. Keep production audit signing enabled.

## 2. Start the stack

From the repository root:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
docker compose -f deploy/docker-compose.yml ps
curl -fsS http://127.0.0.1:8080/api/health
```

Put TLS termination in front of `127.0.0.1:8080`, then verify the public URL
and confirm that browser requests use the same origin. For released images, set
`NIVRIT_VERSION=2.1.0` and omit `--build` after the GHCR packages are public.

## 3. Create the first project

Register the first administrator in the web UI, then create an organization,
project, and environment. Use environment names that match the deployment
boundary, such as `development`, `staging`, and `production`.

Invite teammates only after confirming their email and intended role. Use the
least-privilege project role; use environment overrides when a member must be
denied access to a specific environment.

## 4. Operate secrets safely

- Keep secret values in Nivrit; use stable secret keys and tags for ownership or
  rotation metadata.
- Use the CLI/SDK for automation with a personal access token scoped to the
  required project. Never put a master password, private key, or recovery code
  in CI variables or command-line arguments.
- Rotate project keys after membership changes or suspected exposure, and
  revoke access before removing a user.
- Review and verify the project audit-log chain after sensitive operations.

## 5. Back up and recover

Back up the Postgres volume or a consistent `pg_dump` on a schedule, encrypt it
outside the host, and regularly restore it into an isolated environment. The
database backup contains ciphertext and metadata, not plaintext secret values.
Back up deployment configuration separately through an approved secret store:
`NIVRIT_AUTH_SECRET`, `NIVRIT_TOTP_ENCRYPTION_KEY`, and
`NIVRIT_SIGNING_KEY_SEED` must not be regenerated during a restore.

For example, with [`age`](https://age-encryption.org/) and a recipient key
stored outside the host:

```bash
umask 077
mkdir -p backups
docker compose -f deploy/docker-compose.yml --env-file .env exec -T postgres \
  pg_dump -U "${POSTGRES_USER:-nivrit}" -d "${POSTGRES_DB:-nivrit}" \
  | age -r "$BACKUP_AGE_RECIPIENT" > "backups/nivrit-$(date +%Y%m%d-%H%M%S).sql.age"
```

Restore into an isolated stack first, after confirming the backup checksum:

```bash
age -d backups/nivrit-YYYYMMDD-HHMMSS.sql.age \
  | docker compose -f deploy/docker-compose.yml --env-file .env exec -T postgres \
      psql -U "${POSTGRES_USER:-nivrit}" -d "${POSTGRES_DB:-nivrit}"
```

The backup is still sensitive metadata even though secret values are
ciphertext. Store it encrypted, restrict access, and test the restore regularly.

Test a restore, upgrade, rollback, key rotation, revoked-user path, and failed
password/recovery path before calling the deployment production-ready. Loss of
the client-held private key, master password, and recovery material is
unrecoverable by design.

## 6. Before promotion

Promote the exact immutable release tag, not an unreviewed checkout. Link the
release notes, checksums, SBOM, threat model, limitations, and `SECURITY.md`.
Describe Nivrit as a public MVP/developer preview until an independent review
and real deployment evidence exist. See [`launch-gate.md`](launch-gate.md) and
[`promotion-plan.md`](promotion-plan.md).
