# Cloud KEK operations

`crates/nivrit-crypto/src/kek.rs` defines a `KekBackend` trait (`wrap`/`unwrap`
a data-encryption key) with three implementations: `LocalKek` (AES-256-GCM,
in-process, the default), `AwsKmsKek` (feature `kek-aws`), and
`AzureKeyVaultKek` (feature `kek-azure`). This doc covers provisioning the
cloud side for the latter two.

**Scope.** `KekBackend` is a library-level abstraction in `nivrit-crypto`, not
currently wired to a `nivrit-api` config flag — there is no
`NIVRIT_KEK_BACKEND=aws-kms` server setting today. It exists for anyone
embedding `nivrit-crypto` directly to add centralized key escrow/recovery on
top of nivrit's existing password-derived encryption (see the module doc in
`kek.rs`), and for a future server-side wiring pass. The IAM policies and
Terraform below provision what `AwsKmsKek`/`AzureKeyVaultKek` need regardless
of which side of that line calls them.

## AWS KMS

`AwsKmsKek::new(key_id)` loads credentials via the standard AWS SDK chain and
calls `kms:Encrypt`/`kms:Decrypt` against a symmetric customer master key
(CMK). It needs exactly those two actions — nothing else in the KMS API
surface.

### IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NivritKekWrapUnwrap",
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"
    }
  ]
}
```

Scope `Resource` to the one CMK nivrit uses — not `"*"`, not a key alias
ARN pattern. `kms:GenerateDataKey*`, `kms:CreateKey`, `kms:ScheduleKeyDeletion`
and everything else are deliberately absent: the wrap/unwrap round trip never
needs them, and granting them widens the blast radius of a compromised
credential for no operational benefit.

### Terraform

```hcl
resource "aws_kms_key" "nivrit_kek" {
  description             = "Nivrit KEK"
  deletion_window_in_days = 30
  enable_key_rotation     = true # AWS-managed rotation of the CMK's backing
                                  # key material -- distinct from, and
                                  # unrelated to, nivrit's own project-key
                                  # rotation (ADR 0008).
}

resource "aws_kms_alias" "nivrit_kek" {
  name          = "alias/nivrit-kek"
  target_key_id = aws_kms_key.nivrit_kek.key_id
}

data "aws_iam_policy_document" "nivrit_kek_wrap_unwrap" {
  statement {
    sid       = "NivritKekWrapUnwrap"
    actions   = ["kms:Encrypt", "kms:Decrypt"]
    resources = [aws_kms_key.nivrit_kek.arn]
  }
}

resource "aws_iam_policy" "nivrit_kek_wrap_unwrap" {
  name   = "nivrit-kek-wrap-unwrap"
  policy = data.aws_iam_policy_document.nivrit_kek_wrap_unwrap.json
}

resource "aws_iam_role_policy_attachment" "nivrit_kek" {
  role       = aws_iam_role.nivrit_api.name # the role nivrit-api actually runs as
  policy_arn = aws_iam_policy.nivrit_kek_wrap_unwrap.arn
}
```

`AwsKmsKek::new` takes the key **ID** (or ARN), not the alias — resolve
`aws_kms_alias.nivrit_kek.target_key_id` at deploy time if you'd rather not
hardcode the raw ID.

## Azure Key Vault

`AzureKeyVaultKek` wraps/unwraps via `RSA-OAEP-256` against an RSA key in
Key Vault, authenticating with `DeveloperToolsCredential` locally or any
`TokenCredential` (e.g. a managed identity) via
`AzureKeyVaultKek::new_with_credential` in production. It needs the
`wrapKey`/`unwrapKey` key operations only.

### RBAC role assignment

Key Vault's fine-grained data-plane permissions are set via the
`Key Vault Crypto User` built-in role (grants `wrapKey`/`unwrapKey`/
`encrypt`/`decrypt`, not management operations like key creation or deletion)
scoped to the specific key, not the whole vault:

```bash
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee <principal-id-of-nivrit-api's-identity> \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>/keys/<key-name>"
```

### Terraform

```hcl
resource "azurerm_key_vault_key" "nivrit_kek" {
  name         = "nivrit-kek"
  key_vault_id = azurerm_key_vault.nivrit.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["wrapKey", "unwrapKey"]
}

resource "azurerm_role_assignment" "nivrit_kek_crypto_user" {
  scope                = azurerm_key_vault_key.nivrit_kek.resource_id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.nivrit_api.principal_id
}
```

Key Vault must have RBAC authorization enabled
(`azurerm_key_vault.enable_rbac_authorization = true`) for a key-scoped role
assignment to take effect; the legacy access-policy model only scopes to the
whole vault.

## Common notes

- Both backends are feature-gated (`kek-aws`, `kek-azure` on `nivrit-crypto`)
  and off by default — `cargo check -p nivrit-crypto --features
  kek-aws,kek-azure` compiles them without pulling either SDK into a build
  that doesn't need it.
- Neither backend's credentials or key material ever need to leave the cloud
  provider's boundary: `wrap`/`unwrap` calls send only the DEK ciphertext (or
  plaintext DEK, over TLS, for the duration of one call) — nivrit never
  stores an unwrapped KEK anywhere.
- Rotating the underlying CMK/Key Vault key is the cloud provider's own
  rotation mechanism (`enable_key_rotation` above, or Key Vault's key rotation
  policy) and is unrelated to nivrit's own project-key rotation
  ([ADR 0008](adr/0008-versioned-project-keys.md)) — the two operate at
  different layers and don't need to be coordinated.
