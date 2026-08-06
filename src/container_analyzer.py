"""Container-side entry point for Playwright/Chromium smoke test.

This module provides a minimal test to verify the container can run
Playwright and Chromium successfully as a non-root user.
"""

import asyncio
import sys
import os


async def smoke_test():
    """Run smoke test to verify Playwright/Chromium works in container."""
    print("Starting container smoke test...")
    
    # Check user ID
    uid = os.getuid()
    print(f"Running as UID: {uid}")
    if uid == 0:
        print("ERROR: Running as root - security risk!")
        sys.exit(1)
    
    # Import Playwright
    try:
        from playwright.async_api import async_playwright
        print("Playwright import successful")
    except ImportError as e:
        print(f"ERROR: Failed to import Playwright: {e}")
        sys.exit(1)
    
    # Start Playwright and launch Chromium
    try:
        async with async_playwright() as p:
            print("Starting Playwright...")
            
            # Launch Chromium WITHOUT --no-sandbox (safe inside container)
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--disable-dev-shm-usage',
                    '--disable-download',
                    '--disable-background-networking',
                ]
            )
            print("Chromium launched successfully")
            
            # Create a blank page
            page = await browser.new_page()
            print("Blank page created successfully")
            
            # Navigate to about:blank (no external network)
            await page.goto('about:blank')
            print("Navigated to about:blank successfully")
            
            # Close page and browser
            await page.close()
            await browser.close()
            print("Chromium closed successfully")
            
    except Exception as e:
        print(f"ERROR: Chromium operation failed: {e}")
        sys.exit(1)
    
    print("Smoke test completed successfully!")


if __name__ == "__main__":
    asyncio.run(smoke_test())
