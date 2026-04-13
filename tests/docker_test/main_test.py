import sys
import os
import subprocess
import json

# Add test_suites to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, "test_suites"))

try:
    import direct_test as subtest
    import tun_test
except ImportError:
    # Fallback if tests/test_suites/__init__.py doesn't exist or other issues
    from test_suites import direct_test as subtest
    from test_suites import tun_test

project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))

def setup_coverage_env():
    print("Setting up coverage environment...")
    try:
        # Clean previous coverage
        subprocess.run(["cargo", "llvm-cov", "clean", "--workspace"], cwd=project_root, check=True)
        
        # Get environment variables
        res = subprocess.run(["cargo", "llvm-cov", "show-env", "--export-prefix"], 
                             cwd=project_root, capture_output=True, text=True, check=True)
        
        print("Exporting coverage environment variables:")
        for line in res.stdout.splitlines():
            if not line.startswith("export"): continue
            # Parse export KEY="VALUE"
            parts = line.replace("export ", "").split("=", 1)
            if len(parts) == 2:
                key = parts[0]
                value = parts[1].strip("'\"")
                # print(f"  {key}={value}")
                os.environ[key] = value
        
    except FileNotFoundError:
        print("cargo-llvm-cov not found, aborting coverage setup")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Failed to setup coverage: {e}")
        print(f"STDERR: {e.stderr}")
        sys.exit(1)

def generate_coverage_report():
    print("Generating coverage report...")
    sys.stdout.flush()
    try:
        subprocess.run(
            ["cargo", "llvm-cov", "report", "--codecov", "--output-path", "codecov_docker_test.json"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=True
        )
        print(f"Coverage report generated at {os.path.join(project_root, 'codecov_docker_test.json')}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to generate coverage report: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
    sys.stdout.flush()

def build_clash():
    print("Building clash-rs...")
    # project_root defined globally now
    try:
        result = subprocess.run(
            ["cargo", "build", "-p", "clash-rs", "--message-format=json", "-q"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.splitlines():
            try:
                msg = json.loads(line)
                if msg.get("reason") == "compiler-artifact" and msg.get("target", {}).get("name") == "clash-rs":
                    executable = msg.get("executable")
                    if executable:
                        print(f"Built clash-rs: {executable}")
                        return executable
            except json.JSONDecodeError:
                continue
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        sys.exit(1)
    
    print("Could not find clash-rs executable path in build output.")
    sys.exit(1)

def main():
    print("Starting Main Test Suite...")
    
    setup_coverage_env()
    clash_bin = build_clash()
    
    results = {}
    
    print("\n--- Running Direct Outbound Subtest ---")
    results["direct_test"] = subtest.main(clash_bin=clash_bin)
    
    print("\n--- Running TUN & DNS Hijack Subtest ---")
    results["tun_test"] = tun_test.main(clash_bin=clash_bin)
    
    print("\n--- Test Suite Summary ---")
    all_passed = True
    for test_name, success in results.items():
        status = "PASSED" if success else "FAILED"
        print(f"{test_name}: {status}")
        if not success:
            all_passed = False
            
    if all_passed:
        print("\nALL SUBTESTS PASSED")
        generate_coverage_report()
        sys.exit(0)
    else:
        print("\nSOME SUBTESTS FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()