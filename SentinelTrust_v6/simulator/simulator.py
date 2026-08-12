"""SentinelTrust Attack Replay Simulator"""
import time, random, requests
import logging
logger = logging.getLogger("sentineltrust")

BACKEND = "http://localhost:8000"
DEVICES = ["camera-001","camera-002","sensor-001","sensor-002","router-001","hub-001","plc-001","lock-001"]
ATTACKS = ["mirai","exfiltration","lateral_movement","port_scan"]

def trigger(device_id, attack_type):
    try:
        r = requests.post(f"{BACKEND}/api/v1/simulator/trigger",
            json={"device_id": device_id, "attack_type": attack_type}, timeout=5)
        logger.info(f"Attack {attack_type} on {device_id}: {r.status_code}")
    except Exception as e:
        logger.error(f"Failed: {e}")

def stop(device_id):
    try:
        requests.post(f"{BACKEND}/api/v1/simulator/stop",
            json={"device_id": device_id}, timeout=5)
    except: pass

if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        trigger(sys.argv[1], sys.argv[2])
    else:
        logger.info("Demo loop starting...")
        while True:
            d = random.choice(DEVICES)
            a = random.choice(ATTACKS)
            trigger(d, a)
            time.sleep(30)
            stop(d)
            time.sleep(15)
