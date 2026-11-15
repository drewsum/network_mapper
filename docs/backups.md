# Backups, restore and export

## What's backed up

The `backup` service in the server stack dumps the whole database with `pg_dump` once a day
into `<NETMAP_DATA_DIR>/backups`: devices and their names, history, ports, DNS lookups and
aggregates, alerts and rules, settings made in the UI, blocklists. The env vars and
`.env` aren't in it, so keep a copy of those (in a password manager, say).

- Files are named for when they were made, e.g. `netmap-20261115T031622Z.dump` (UTC), in
  pg_dump's compressed custom format. A month of a home network is a few MB.
- A dump is made when the newest is older than `NETMAP_BACKUP_INTERVAL_HOURS` (24), so
  restarting the stack doesn't make extra ones. The newest `NETMAP_BACKUP_KEEP` (14) are kept;
  older ones are deleted.
- The directory and files are readable by the netmap user (uid 10001) only.
- Each run's result shows on the **System** page. A failed backup also shows as a banner on
  every page, and is tried again an hour later.

These dumps sit on the same pool as the database. For protection against losing the pool,
include the dataset in a TrueNAS replication or cloud sync task, or copy `backups/` elsewhere.
ZFS snapshots of the dataset are a good extra layer, but a snapshot of a running database's
files is only crash-consistent; the dumps are the clean copy.

### A backup now

```sh
# plain compose, in the checkout
sudo docker compose exec -u netmap backup netmap backup --once
# Portainer stack, over SSH
sudo docker exec -u netmap netmap-backup-1 netmap backup --once
```

## Restoring

A restore **replaces** the database with the dump's contents. Everything recorded since that
dump is lost, so take a fresh backup first if the current data is worth anything.

The server must run the same TimescaleDB image as the one that made the dump (the compose files
pin `timescale/timescaledb:2.17.2-pg16`). A dump from an older netmap is fine: the restore runs
the migrations afterwards.

1. **Stop the api and collector**, so nothing writes while the database is replaced. The
   restore refuses to start while anything else is connected.

   ```sh
   sudo docker compose stop api collector          # plain compose
   sudo docker stop netmap-api-1 netmap-collector-1  # Portainer, over SSH
   ```

2. **Pick a dump** and run the restore in the backup container, as the netmap user (`-u
   netmap`; the container's root has no capabilities and can't read the files):

   ```sh
   sudo docker exec -u netmap netmap-backup-1 ls -l /backups
   sudo docker exec -u netmap netmap-backup-1 netmap restore /backups/netmap-20261115T031622Z.dump --yes
   ```

   (With plain compose, `sudo docker compose exec -u netmap backup netmap restore ... --yes`.)
   It drops and recreates the database, restores the dump with TimescaleDB's
   `timescaledb_pre_restore()` / `timescaledb_post_restore()` steps, then runs the
   migrations. It stops at the first error and says what failed. Without `--yes` it only says
   what it would do.

3. **Start the api and collector again:**

   ```sh
   sudo docker compose start api collector
   sudo docker start netmap-collector-1 netmap-api-1
   ```

To restore a dump from elsewhere, copy it into `<NETMAP_DATA_DIR>/backups` first and make it
readable by uid 10001 (`chown 10001` it).

### Trying a dump without touching the live data

`--database` restores into a separate database instead, which is created (or replaced) and
left alone afterwards; the app keeps running on its own. Look around with `psql`, then drop it:

```sh
sudo docker exec -u netmap netmap-backup-1 netmap restore /backups/<file> --database netmap_restore_test
sudo docker exec netmap-db-1 psql -U netmap -d netmap -c "SELECT count(*) FROM devices"
sudo docker exec netmap-db-1 psql -U netmap -d netmap_restore_test -c "SELECT count(*) FROM devices"
sudo docker exec netmap-db-1 psql -U netmap -d postgres -c "DROP DATABASE netmap_restore_test WITH (FORCE)"
```

### How this was tested

On the TrueNAS host, a production dump (2.2 MB) was restored into a second, freshly deployed
stack in 40 seconds. Every table matched production row for row up to the moment of the dump
(devices, events, ports, IPs, baselines, 35,736 blocklist entries, 38,785 DNS queries, daily
aggregates), along with TimescaleDB's 2 hypertables, 3 continuous aggregates and 13 policy
jobs. Restoring the same dump with `--database` beside the running app took 20 seconds.

## Exporting data

The **System** page has CSV and JSON downloads of each table worth keeping: devices, IP
addresses, open ports, UPnP port forwards, device events, alerts, and DNS lookups per device,
domain and day. Pick a time range for the ones that grow (events, alerts, DNS); the rest are
always exported whole.

The same exports are in the API, for scripts (log in first, or send the session cookie):

```sh
GET /api/export                          # what can be exported
GET /api/export/devices.csv
GET /api/export/events.json?days=30
GET /api/export/dns_daily.csv?days=365
```

Exports are for spreadsheets and other tools, not for restoring: use the dumps for that.
