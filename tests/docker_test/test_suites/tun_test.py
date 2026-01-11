import socket
import subprocess
import time
import os
import shutil
import tempfile
import sys
import signal

# Configuration
CLASH_PORT = 7891
DNS_PORT = 5353
FAKE_IP_RANGE = "198.18.0.0/16"
TEST_DOMAIN = "test.clash.rs"

def wait_for_port(port, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.5)
    return False

def test_dns_hijack_and_fake_ip():
    print(f"Testing DNS hijacking and Fake-IP for {TEST_DOMAIN}...")
    
    try:
        # According to user request, we should not assign a DNS server in the command.
        # This tests if Clash successfully hijacks standard DNS traffic.
        print(f"Querying for {TEST_DOMAIN} (expecting hijacking to Fake-IP)...")
        # Give it a bit more time for TUN to stabilize
        time.sleep(3)
        
        output = ""
        # Try nslookup without server
        try:
            result = subprocess.run(
                ["nslookup", TEST_DOMAIN],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout
        except Exception:
            pass

        if not output or "198.18." not in output:
            # Try dig as fallback without server
            try:
                result = subprocess.run(
                    ["dig", TEST_DOMAIN],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = result.stdout
            except Exception:
                pass

        print(f"DNS Output Summary: {output.strip().splitlines()[-5:] if output else 'None'}")
        
        # Check if output contains a Fake-IP (198.18.x.x)
        if output and "198.18." in output:
            print("Fake-IP detected in DNS response: PASSED")
            return True
        else:
            print("Fake-IP NOT detected in DNS response: FAILED")
            return False
            
    except Exception as e:
        print(f"DNS test failed: {e}")
        return False

def main(clash_bin=None):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
    run_dir = tempfile.mkdtemp(prefix="clash_tun_")
    
    print(f"Project root: {project_root}")
    print(f"Run dir: {run_dir}")

    config_path = os.path.join(run_dir, "config.yaml")
    with open(config_path, "w") as f:
        f.write(f"""
mixed-port: {CLASH_PORT}
mode: rule
ipv6: false
log-level: debug
external-controller: 127.0.0.1:9096

dns:
  enable: true
  listen: 0.0.0.0:{DNS_PORT}
  enhanced-mode: fake-ip
  fake-ip-range: {FAKE_IP_RANGE}
  nameserver:
    - 114.114.114.114

tun:
  enable: true
  device-id: utun1989
  route-all: true
  gateway: 198.18.0.1/30
  dns-hijack: true

rules:
  - MATCH,DIRECT
""")

    # Symlink required database files
    for db_file in ["Country.mmdb", "geosite.dat"]:
        src = os.path.join(project_root, db_file)
        dst = os.path.join(run_dir, db_file)
        if os.path.exists(src):
            os.symlink(src, dst)

    # Start Clash-rs
    clash_log_path = os.path.join(run_dir, "clash.log")
    clash_log_file = open(clash_log_path, "w")
    if clash_bin:
        print(f"Starting clash-rs using pre-built binary: {clash_bin}")
        print(f"DEBUG: tun_test LLVM_PROFILE_FILE={os.environ.get('LLVM_PROFILE_FILE')}")
        clash_proc = subprocess.Popen(
            [clash_bin, "-d", run_dir],
            cwd=project_root,
            stdout=clash_log_file,
            stderr=subprocess.STDOUT,
            env=os.environ.copy()
        )
    else:
        print("Building and starting clash-rs using cargo run...")
        clash_proc = subprocess.Popen(
            ["cargo", "run", "-p", "clash-rs", "--", "-d", run_dir],
            cwd=project_root,
            stdout=clash_log_file,
            stderr=subprocess.STDOUT,
        )

    success = False
    try:
        print(f"Waiting for clash-rs DNS to start on port {DNS_PORT}...")
        # DNS is UDP, so wait_for_port (TCP) might not work perfectly, 
        # but Clash usually has other ports open too.
        # Let's wait for mixed-port instead.
        if wait_for_port(CLASH_PORT):
            print("Clash-rs started.")
            time.sleep(2) 

            success = test_dns_hijack_and_fake_ip()
            if not success:
                print("--- Clash Logs ---")
                clash_log_file.flush()
                with open(clash_log_path, "r") as f:
                    print(f.read())
                print("------------------")
        else:
            print("Timeout waiting for clash-rs.")
    finally:
        print("Cleaning up...")
        if clash_proc.poll() is None:
            clash_proc.send_signal(signal.SIGINT)
            try:
                clash_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print("clash-rs did not exit gracefully, killing...")
                clash_proc.kill()

        
        shutil.rmtree(run_dir)
    return success

if __name__ == "__main__":
    # If run standalone without main_test.py
    if main():
        sys.exit(0)
    else:
        sys.exit(1)
