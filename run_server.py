import asyncio
import sys
import uvicorn

if sys.platform == "win32":
    asyncio.set_event_loop_policy(
        asyncio.WindowsProactorEventLoopPolicy()
    )

print(
    "Event loop policy:",
    type(asyncio.get_event_loop_policy()).__name__
)

import os

port = int(os.getenv("PORT", "8000"))
host = os.getenv("HOST", "0.0.0.0")

print(f"Starting server on {host}:{port}")

uvicorn.run(
    "web.app:app",
    host=host,
    port=port,
    reload=False
)
