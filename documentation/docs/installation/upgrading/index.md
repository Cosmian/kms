# Upgrading the KMS

Every release page lists what changes by area and what to do on an existing installation. The procedure below applies to every release.

## Upgrade procedure

1. Read the release page for your target version and apply its **What to do** column.
2. Check that your source version is supported: see [supported source versions](./database_migrations.md#supported-source-versions).
3. Take a cold backup with the server stopped. For SQLite, copy the whole `sqlite_path` directory (`cp -a`). For the other backends, use the backend's own dump tool.
4. Stop every node: do not run two versions of the server against one database.
5. Upgrade the server, `ckms` and the packages together, then start the server. The database migrates at startup; see [Database Migrations](./database_migrations.md).
6. Run the "Verify the upgrade" list of the release page.
7. To go back, restore the pre-upgrade backup and the pre-upgrade `kms.toml`, and start the old binary.

## Release pages

| Release | Page | Highlights |
|---|---|---|
| 5.30 | [Upgrading to 5.30](./upgrade_to_5_30.md) | Secure-by-default configuration and identities, KMIP 2.1 conformance, versioned database migrations, multi-node cluster support |

Releases earlier than 5.30 are documented in the changelog (`CHANGELOG.md` in the repository root).
