"""Run the standalone portal Telegram worker."""
import asyncio
import logging
import sys

from . import main


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr,
                        format='[telegram-bot] %(levelname)s %(message)s')
    asyncio.run(main())
