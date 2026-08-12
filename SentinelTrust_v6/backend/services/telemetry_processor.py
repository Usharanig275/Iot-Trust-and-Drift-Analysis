"""Background loop: no-op tick. WebSocket broadcasting of per-user scores
is handled on-demand from the frontend polling /api/v1/trust/scores.
This loop just keeps the WebSocket alive."""
import asyncio, time, logging
logger = logging.getLogger("sentineltrust")

class TelemetryProcessor:
    def __init__(self, trust_engine, ws_manager):
        self.engine = trust_engine
        self.ws = ws_manager

    async def run_scoring_loop(self):
        logger.info("Telemetry loop started (heartbeat only)")
        while True:
            try:
                await self.ws.broadcast({"type": "heartbeat", "timestamp": time.time()})
            except Exception as e:
                logger.error(f"Telemetry loop error: {e}")
            await asyncio.sleep(10)
