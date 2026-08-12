# Backup and recovery

Treat the following as one recovery unit:

1. The Infractory application database.
2. The Pulumi PostgreSQL backend database.
3. `APP_ENCRYPTION_KEY`.
4. `PULUMI_CONFIG_PASSPHRASE`.

Back up both databases using consistent PostgreSQL snapshots and store the two external secrets separately from the database backup. Losing Pulumi state blocks automatic destructive operations; Infractory must not compensate with broad tag-based deletion.

## Restore drill

At every release, restore into an isolated installation and prove that a pre-existing environment can be refreshed, planned, updated, and destroyed. Validate that node agents reconnect without re-enrollment and that no secret plaintext appears in restored logs or operation events.
