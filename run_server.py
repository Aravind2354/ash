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

uvicorn.run(
    "web.app:app",
    host="0.0.0.0",
    port=8000,
    reload=False
)
