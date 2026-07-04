#!/usr/bin/env python3
import os
import sys
import json
import time
import subprocess
import requests
import redis

# ==============================================================================
# CONFIGURATION
# ==============================================================================
REDIS_HOST = os.getenv("REDIS_HOST", "192.168.52.1") # Change to your Host IP
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_QUEUE = os.getenv("REDIS_QUEUE", "queues:ulp_parser") # Queue to listen to
CALLBACK_URL = os.getenv("CALLBACK_URL", "http://192.168.52.1:8000/api/v1/jobs/callback")

# The command to execute on the VM. Use {value} as a placeholder for the asset.
# Example: "python telegram-worker-a.py {value}"
# Example: "python search_and_index.py {value} --file /path/to/combo.tsv"
COMMAND_TEMPLATE = os.getenv("COMMAND_TEMPLATE", "python search_and_index.py {value} --file 2.4\ Billion\ URL\ Login\ Pass/2.4_Billion_url_login_pass.tsv")

def main():
    print("=" * 60)
    print("🚀 Starting DarkTrace Redis Worker Runner Daemon")
    print(f"   Queue   : {REDIS_QUEUE}")
    print(f"   Redis   : {REDIS_HOST}:{REDIS_PORT}")
    print(f"   Command : {COMMAND_TEMPLATE}")
    print(f"   Callback: {CALLBACK_URL}")
    print("=" * 60)

    try:
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            db=0,
            socket_timeout=5
        )
        # Test connection
        r.ping()
        print("[+] Successfully connected to Redis.")
    except Exception as e:
        print(f"[!] Error: Cannot connect to Redis: {e}")
        sys.exit(1)

    while True:
        try:
            # Blocking pop (waits indefinitely for a job)
            print("[*] Waiting for new job...")
            _, message_bytes = r.brpop(REDIS_QUEUE, timeout=0)
            
            # Parse JSON message
            job_data = json.loads(message_bytes.decode("utf-8"))
            job_id = job_data.get("job_id")
            asset_value = job_data.get("asset_value")
            
            if not job_id or not asset_value:
                print("[-] Received invalid job data. Skipping.")
                continue

            print(f"\n[+] Job Received! ID: {job_id} | Asset: {asset_value}")
            
            # Format command
            cmd = COMMAND_TEMPLATE.format(value=subprocess.list2cmdline([asset_value]))
            print(f"[*] Executing: {cmd}")
            
            # Execute script on the VM
            t0 = time.time()
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            elapsed = time.time() - t0
            
            status = "completed" if result.returncode == 0 else "failed"
            print(f"[+] Execution finished in {elapsed:.1f}s with status: {status}")
            
            if result.stdout:
                print("--- stdout ---")
                print(result.stdout.strip())
            if result.stderr:
                print("--- stderr ---")
                print(result.stderr.strip())
            print("--------------")

            # Send HTTP Callback notification to Laravel Host
            callback_payload = {
                "job_id": job_id,
                "status": status,
                "worker": REDIS_QUEUE,
                "elapsed": elapsed
            }
            
            try:
                resp = requests.post(CALLBACK_URL, json=callback_payload, timeout=60)
                print(f"[+] Callback response: {resp.status_code} {resp.reason}")
            except Exception as callback_err:
                print(f"[!] Callback failed: {callback_err}")
                
        except KeyboardInterrupt:
            print("\n[*] Exiting worker daemon gracefully.")
            break
        except Exception as e:
            print(f"[!] Unexpected runner error: {e}")
            time.sleep(2) # Prevent rapid loop crashing on persistent errors

if __name__ == "__main__":
    main()
