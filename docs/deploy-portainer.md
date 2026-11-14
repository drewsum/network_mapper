# Deploying on TrueNAS with Portainer

The server runs netmap as a Portainer **Git-repository stack** from
`deploy/portainer-compose.yml`. Nothing is published to a registry. The Portainer TrueNAS app
can't run image builds (it fails with `mkdir /.docker: permission denied`), so the image is
built on the host over SSH with `scripts/build-on-host.sh`, and the stack uses `netmap:local`
with `pull_policy: never`. The API container also serves the built UI, so there's no separate
web container.

| Service | Network | Purpose |
|---|---|---|
| `db` | bridge, DB port published on `127.0.0.1` only | TimescaleDB, data in `${NETMAP_DATA_DIR}/db` |
| `migrate` | bridge | one-off: migrations + retention policies, then exits |
| `api` | bridge, `${NETMAP_API_PUBLISH_PORT}` published | API + UI |
| `collector` | host, `NET_RAW` | LAN discovery (ARP sweep + passive listening), weekly MAC vendor registry download from the IEEE; reaches the DB on its loopback port |

## One-time setup

1. **Dataset.** Create a dataset for the project (Generic preset), e.g.
   `/mnt/<pool>/<dataset>/network_mapper`. The DB container creates and owns `db/` inside it
   on first start.
2. **Portainer user.** Create a non-admin user (e.g. `netmap-dev`) with access to the Docker
   environment, and an access token for it. Stacks it creates are visible only to it and to
   admins. Other stacks should not be set to *Public* access control, or this user can manage
   them too.
3. **Repo access.** A GitHub fine-grained token with read-only **Contents** access to this
   repo only. Portainer uses it to clone.
4. **SSH (optional).** A TrueNAS user with key-only login, a home directory inside the project
   dataset, and *Allowed sudo commands with no password* set to `/usr/bin/docker` only. Leave
   *Allow all sudo commands with no password* off. TrueNAS hides the `docker` group from the
   user form, and editing `/etc/group` by hand doesn't survive, so sudo is the way in. Note
   that docker access is effectively root on the host.

Keep the tokens and the dataset path out of the repo. On the dev PC they live outside the
working tree.

## Creating the stack

In Portainer, as the non-admin user: **Stacks → Add stack → Repository**.

- Repository URL: this repo's HTTPS URL. Reference: `refs/heads/main` (or a branch under test).
- Authentication: on, with the GitHub username and the read-only token.
- Compose path: `deploy/portainer-compose.yml`.
- Environment variables: every variable from `.env.example`, filled in. Also set
  `NETMAP_DATA_DIR` to the dataset path. The dev-only `NETMAP_WEB_PUBLISH_PORT` isn't used.

The compose file passes each setting to the containers explicitly as `${VAR:-}`, because
Portainer doesn't write a `stack.env` file that compose can read for Git stacks. When you add a
new `NETMAP_*` setting, add it to `x-netmap-env` in `deploy/portainer-compose.yml` too.

Build the image first (`bash scripts/build-on-host.sh`, see the dev loop), then deploy and check that `db` and `api` are healthy, `migrate` exited with code 0, and
`collector` is healthy. The UI is at `http://<truenas-host>:<NETMAP_API_PUBLISH_PORT>`.

## Environment variables

Same as `.env.example`, plus:

| Variable | Purpose |
|---|---|
| `NETMAP_DATA_DIR` | Host path of the project dataset. The DB lives in `<this>/db`. Required. |
| `NETMAP_API_PUBLISH_PORT` | Host port for the API and UI (default 8000). Pick one no other app uses. |
| `NETMAP_DB_PUBLISH_PORT` | Loopback-only DB port (default 5433). The collector connects through it. |

## Dev loop

1. Develop on the dev PC and run `bash scripts/test.sh`, then commit and push a branch.
2. Build the image on the host: `bash scripts/build-on-host.sh [ref]`. It streams
   `git archive` of the ref over SSH into `sudo docker build`, so the host needs no checkout and
   no GitHub token.
3. Point the stack at that branch (or merge to `main`) and redeploy with *Pull and redeploy*,
   in the UI or through the Portainer API. The containers are recreated from the new image.
4. Check container health and logs through Portainer. Over SSH, use `sudo docker logs` or
   `sudo docker exec` against the `netmap` containers only.

## Ground rules on the server

Only touch the netmap stack, its images and its dataset. Don't change pools, shares, network
settings, or other stacks or apps. Ask the owner before publishing new ports or anything else
that affects the wider system.
