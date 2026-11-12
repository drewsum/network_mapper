"""`netmap <command>` — single entry point for every container role."""

import argparse
import logging
from pathlib import Path

from netmap.config import get_settings

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


def cmd_migrate(_: argparse.Namespace) -> None:
    from alembic import command
    from alembic.config import Config

    from netmap.db import get_engine
    from netmap.db.policies import apply_policies

    command.upgrade(Config(str(ALEMBIC_INI)), "head")
    with get_engine().begin() as conn:
        apply_policies(conn, get_settings())


def cmd_api(_: argparse.Namespace) -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "netmap.api.app:create_app",
        factory=True,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
    )


def cmd_collector(_: argparse.Namespace) -> None:
    import asyncio

    from netmap.collector.main import run

    asyncio.run(run(get_settings()))


def cmd_seed(args: argparse.Namespace) -> None:
    from netmap.seed.main import seed

    seed(get_settings(), days=args.days, reset=args.reset, rng_seed=args.rng_seed)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="netmap")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="apply DB migrations and Timescale policies").set_defaults(
        func=cmd_migrate
    )
    sub.add_parser("api", help="run the web API").set_defaults(func=cmd_api)
    sub.add_parser("collector", help="run the collector").set_defaults(func=cmd_collector)
    seed_p = sub.add_parser("seed", help="fill the DB with synthetic devices and DNS activity")
    seed_p.add_argument("--days", type=int, default=30)
    seed_p.add_argument("--reset", action="store_true", help="wipe existing data first")
    seed_p.add_argument("--rng-seed", type=int, default=1234)
    seed_p.set_defaults(func=cmd_seed)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=get_settings().log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args.func(args)


if __name__ == "__main__":
    main()
