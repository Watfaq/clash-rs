import socket
import threading
import subprocess
import time
import os
import signal
import sys
import shutil
import tempfile

try:
    import socks
except ImportError:
    try:
        import socks_client.tcp_sync as socks_tcp
        import socks_client.udp_sync as socks_udp
        socks = socks_tcp  # Default to TCP for simple usage if needed
    except ImportError:
        print("Error: socks-client not installed. Please install it via pip or use uv.")
        sys.exit(1)

# Configuration
CLASH_PORT = 7890
TCP_ECHO_PORT = 12345
UDP_ECHO_PORT = 12345
HOST = "127.0.0.1"

def tcp_echo_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, TCP_ECHO_PORT))
    sock.listen(1)
    # print(f"TCP Echo server listening on {HOST}:{TCP_ECHO_PORT}")
    try:
        while True:
            conn, addr = sock.accept()
            # print(f"TCP Connected by {addr}")
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)
            conn.close()
    except Exception:
        pass
    finally:
        sock.close()

def udp_echo_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, UDP_ECHO_PORT))
    # print(f"UDP Echo server listening on {HOST}:{UDP_ECHO_PORT}")
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            # print(f"UDP Received {data} from {addr}")
            sock.sendto(data, addr)
    except Exception:
        pass
    finally:
        sock.close()

def wait_for_port(port, timeout=600):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((HOST, port), timeout=1):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.5)
    return False

def test_tcp_proxy():
    print("Testing TCP Proxy...")
    if 'socks_tcp' in globals():
        s = socks_tcp.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks_tcp.SOCKS5, HOST, CLASH_PORT)
    else:
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, HOST, CLASH_PORT)
    try:
        s.connect((HOST, TCP_ECHO_PORT))
        msg = b"Hello TCP"
        s.sendall(msg)
        data = s.recv(1024)
        if data == msg:
            print("TCP Proxy Test: PASSED")
            return True
        else:
            print(f"TCP Proxy Test: FAILED (Expected {msg}, got {data})")
            return False
    except Exception as e:
        print(f"TCP Proxy Test: FAILED ({e})")
        return False
    finally:
        s.close()

def test_udp_proxy():
    print("Testing UDP Proxy...")
    if 'socks_udp' in globals():
        # socks-client's udp_sync requires setting a default proxy or passing it to constructor
        # based on our investigation of set_default_proxy
        socks_udp.set_default_proxy(socks_udp.SOCKS5, HOST, CLASH_PORT)
        s = socks_udp.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        s.set_proxy(socks.SOCKS5, HOST, CLASH_PORT)
    
    try:
        msg = b"Hello UDP"
        # Increase timeout for UDP Associate handshake
        s.settimeout(10)
        s.sendto(msg, (HOST, UDP_ECHO_PORT))
        
        data, addr = s.recvfrom(1024)
        if data == msg:
            print("UDP Proxy Test: PASSED")
            return True
        else:
            print(f"UDP Proxy Test: FAILED (Expected {msg}, got {data})")
            return False
    except Exception as e:
        print(f"UDP Proxy Test: FAILED ({e})")
        import traceback
        traceback.print_exc()
        return False
    finally:
        s.close()

def main(clash_bin=None):
    # Setup workspace
    # Since this file is now in tests/test_suites/, root is 3 levels up
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
    run_dir = tempfile.mkdtemp(prefix="clash_test_")
    
    print(f"Project root: {project_root}")
    print(f"Run dir: {run_dir}")

    config_path = os.path.join(run_dir, "config.yaml")
    with open(config_path, "w") as f:
        f.write(f"""
mixed-port: {CLASH_PORT}
mode: rule
ipv6: false
log-level: debug
external-controller: 127.0.0.1:9095
rules:
  - MATCH,DIRECT
""")

    # Symlink required database files
    for db_file in ["Country.mmdb", "geosite.dat"]:
        src = os.path.join(project_root, db_file)
        dst = os.path.join(run_dir, db_file)
        if os.path.exists(src):
            os.symlink(src, dst)
        else:
            print(f"Warning: {db_file} not found in project root. Clash might fail.")

    # Start Echo Servers
    tcp_thread = threading.Thread(target=tcp_echo_server, daemon=True)
    udp_thread = threading.Thread(target=udp_echo_server, daemon=True)
    tcp_thread.start()
    udp_thread.start()

    # Start Clash-rs
    if clash_bin:
        print(f"Starting clash-rs using pre-built binary: {clash_bin}")
        clash_proc = subprocess.Popen(
            [clash_bin, "-d", run_dir],
            cwd=project_root,
        )
    else:
        print("Building and starting clash-rs using cargo run...")
        clash_proc = subprocess.Popen(
            ["cargo", "run", "-p", "clash-rs", "--", "-d", run_dir],
            cwd=project_root,
        )

    success = False
    try:
        print(f"Waiting for clash-rs to start on port {CLASH_PORT}...")
        if wait_for_port(CLASH_PORT):
            print("Clash-rs started.")
            time.sleep(2) # Give it a moment to stabilize

            tcp_success = test_tcp_proxy()
            udp_success = test_udp_proxy()

            if tcp_success and udp_success:
                print("\nDIRECT TEST: PASSED")
                success = True
            else:
                print("\nDIRECT TEST: FAILED")
        else:
            print("Timeout waiting for clash-rs to listen.")
    finally:
        print("Cleaning up...")
        clash_proc.terminate()
        try:
            clash_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            clash_proc.kill()
        
        shutil.rmtree(run_dir)
    return success

if __name__ == "__main__":
    if main():
        sys.exit(0)
    else:
        sys.exit(1)