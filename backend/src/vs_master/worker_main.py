"""Run master telemetry, expiry, and durable device-op retries off the web loop."""
import asyncio
import logging

from .models import make_engine
from .worker import process_pending

logger = logging.getLogger(__name__)


async def serve(engine, interval=45, sleep=asyncio.sleep):
    while True:
        try:
            await asyncio.to_thread(process_pending, engine)
        except Exception as exc:
            # Bridge failures can contain URLs or credentials; log only the type.
            logger.error('Master worker pass failed (%s)', type(exc).__name__)
        await sleep(interval)


def main():
    engine = make_engine()
    try:
        asyncio.run(serve(engine))
    finally:
        engine.dispose()


if __name__ == '__main__':
    main()
