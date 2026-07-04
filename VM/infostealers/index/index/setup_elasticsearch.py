#!/usr/bin/env python3
"""
Set up and run Elasticsearch standalone (no Docker required).

Downloads Elasticsearch 8.19.2 and runs it in single-node mode.
Windows-only â€” uses the official .zip distribution.
"""
import os
import sys
import time
import subprocess
import urllib.request
import zipfile
import shutil
import signal

ES_VERSION = "8.19.2"
ES_DIST = f"elasticsearch-{ES_VERSION}-windows-x86_64.zip"
ES_URL = f"https://artifacts.elastic.co/downloads/elasticsearch/{ES_DIST}"
INSTALL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "elasticsearch-standalone")
ES_DIR = os.path.join(INSTALL_DIR, "elasticsearch")
PORT = 9200


def download_es():
    print(f"Downloading Elasticsearch {ES_VERSION} ...")
    path = os.path.join(INSTALL_DIR, ES_DIST)
    if os.path.exists(path):
        print(f"  File already exists: {path}")
        return path
    os.makedirs(INSTALL_DIR, exist_ok=True)
    urllib.request.urlretrieve(ES_URL, path)
    print(f"  Downloaded: {path} ({os.path.getsize(path) / 1024**2:.0f} MB)")
    return path


def extract_es(zip_path):
    print("Extracting ...")
    if os.path.exists(ES_DIR):
        print(f"  Already extracted: {ES_DIR}")
        return
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(INSTALL_DIR)
    # The zip extracts a folder named elasticsearch-<version>; rename it
    extracted = os.path.join(INSTALL_DIR, f"elasticsearch-{ES_VERSION}")
    if os.path.exists(extracted):
        shutil.move(extracted, ES_DIR)
    print(f"  Extracted to: {ES_DIR}")


def write_config():
    """Disable security and set single-node."""
    conf_dir = os.path.join(ES_DIR, "config")
    es_yaml = os.path.join(conf_dir, "elasticsearch.yml")

    # Ensure config exists with required settings
    if os.path.exists(es_yaml):
        with open(es_yaml, "r") as f:
            content = f.read()
        if "xpack.security.enabled" not in content:
            with open(es_yaml, "a") as f:
                f.write("\n# Disable security\nxpack.security.enabled: false\n")
    else:
        with open(es_yaml, "w") as f:
            f.write(f"""discovery.type: single-node
xpack.security.enabled: false
""")


def start_es():
    """Start Elasticsearch in a background process."""
    print("Starting Elasticsearch ...")
    java_home = os.environ.get("JAVA_HOME")
    if not java_home:
        print("  JAVA_HOME not set. Trying to find Java ...")
        # Common Java locations on Windows
        for candidate in [
            r"C:\Program Files\Java\jdk-*\bin",
            r"C:\Program Files\Eclipse Adoptium\jdk-*\bin",
        ]:
            import glob as g
            for j in g.glob(candidate):
                java_home = os.path.dirname(j)
                os.environ["JAVA_HOME"] = java_home
                break
            if java_home:
                break

    if not java_home:
        print("  âŒ Java not found. Elasticsearch requires JDK 17+ installed.")
        print("  Download from: https://adoptium.net/")
        print("  Then set: setx JAVA_HOME \"<path-to-jdk>\"")
        sys.exit(1)

    es_home = ES_DIR
    bat = os.path.join(es_home, "bin", "elasticsearch.bat")

    if not os.path.exists(bat):
        print(f"  âŒ elasticsearch.bat not found at {bat}")
        sys.exit(1)

    # Start in background
    proc = subprocess.Popen(
        [bat],
        cwd=es_home,
        env={**os.environ, "ES_HOME": es_home, "JAVA_HOME": java_home},
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
    )
    print(f"  Started Elasticsearch (PID {proc.pid})")
    return proc


def wait_for_es(max_wait=120):
    from urllib.request import urlopen, URLError
    url = f"http://localhost:{PORT}"
    print(f"  Waiting for Elasticsearch at {url} ...")
    start = time.time()
    while time.time() - start < max_wait:
        try:
            urlopen(url, timeout=5)
            print("  âœ“ Elasticsearch is up!")
            return True
        except (URLError, OSError):
            time.sleep(5)
    print("  âŒ Timed out waiting for Elasticsearch")
    return False


def main():
    print("=" * 60)
    print("Elasticsearch Standalone Setup")
    print("=" * 60)

    # Check Java
    print("\nChecking Java ...")
    java_cmd = "java"
    try:
        result = subprocess.run([java_cmd, "-version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  [OK] Java found: {result.stderr.strip().splitlines()[0]}")
        else:
            print("  âŒ Java not found or failed")
            print("  Install JDK 17+ from https://adoptium.net/")
            sys.exit(1)
    except FileNotFoundError:
        print("  âŒ Java not in PATH. Install JDK 17+ and restart.")
        sys.exit(1)

    # Download
    zip_path = download_es()

    # Extract
    extract_es(zip_path)

    # Config
    write_config()

    # Start
    proc = start_es()

    # Wait
    if wait_for_es():
        print("\n" + "=" * 60)
        print("âœ“ Elasticsearch is ready at http://localhost:9200")
        print("=" * 60)
        print("\nTo index victims.jsonl:")
        print(f"  python indexer.py setup")
        print(f"  python indexer.py index victims.jsonl")
        print("\nTo stop Elasticsearch:")
        print(f"  taskkill /F /IM java.exe  (or kill PID {proc.pid})")
        print("\nNote: This process will keep running in the background.")
        print("Run this script again or use 'indexer.py' to manage.")
    else:
        print("  Elasticsearch failed to start. Check logs at:")
        print(f"    {ES_DIR}/logs/")
        proc.terminate()
        sys.exit(1)


if __name__ == "__main__":
    main()

