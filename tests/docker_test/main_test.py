import sys
import os
import subprocess
import json

# Add test_suites to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, "test_suites"))

try:
    import direct_test as subtest
except ImportError:
    # Fallback if tests/test_suites/__init__.py doesn't exist or other issues
    from test_suites import direct_test as subtest

def build_clash():
    print("Building clash-rs...")
    project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
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
    
    clash_bin = build_clash()
    
    results = {}
    
    print("\n--- Running Direct Outbound Subtest ---")
    results["direct_test"] = subtest.main(clash_bin=clash_bin)
    
    print("\n--- Test Suite Summary ---")
    all_passed = True
    for test_name, success in results.items():
        status = "PASSED" if success else "FAILED"
        print(f"{test_name}: {status}")
        if not success:
            all_passed = False
            
    if all_passed:
        print("\nALL SUBTESTS PASSED")
        sys.exit(0)
    else:
        print("\nSOME SUBTESTS FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()