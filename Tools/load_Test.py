import threading
import time
import random
import sys

try:
    import requests
except ImportError:
    print("Please run: pip install requests")
    sys.exit(1)

# --- Configuration ---
TARGET_URL = "http://127.0.0.1"  # Port 80 is implied
CONCURRENT_USERS = 50            # Number of threads
REQUESTS_PER_USER = 20           # How many requests each thread sends
TOTAL_REQUESTS = CONCURRENT_USERS * REQUESTS_PER_USER

# --- Paths to Spam ---
# We mix valid paths, PHP scripts, and 404s to test different logic branches
PATHS = [
    "/",                    # Root (Static or Index)
    "/index.php",           # PHP Execution
    "/server.py",           # Forbidden File (Should return 403)
    "/admin.php",           # Likely 404 (Test error logging)
    "/logo.png",            # Static file simulation
    "/.htaccess",           # Forbidden (Should return 403)
    "/api/v1/status",       # Deep path
    "/login.php?user=admin" # Query params
]

# Stats
success_count = 0
error_count = 0
lock = threading.Lock()

def worker(user_id):
    global success_count, error_count
    
    # Create a session for connection pooling (simulates a real browser)
    session = requests.Session()
    
    for _ in range(REQUESTS_PER_USER):
        path = random.choice(PATHS)
        url = f"{TARGET_URL}{path}"
        
        try:
            # Randomize method (GET vs POST)
            if random.random() > 0.8:
                resp = session.post(url, data={"test": "data"})
            else:
                resp = session.get(url)
            
            with lock:
                success_count += 1
                # Print a dot for progress, flush immediately
                print(".", end="", flush=True)
                
        except requests.exceptions.RequestException:
            with lock:
                error_count += 1
                print("x", end="", flush=True)
        
        # Slight jitter so they don't all hit at the exact same millisecond
        time.sleep(random.uniform(0.01, 0.1))

def run_test():
    print(f"🚀 Starting Load Test on {TARGET_URL}")
    print(f"👥 Users: {CONCURRENT_USERS} | 📨 Reqs/User: {REQUESTS_PER_USER}")
    print(f"📦 Total Expected Requests: {TOTAL_REQUESTS}")
    print("-" * 40)

    start_time = time.time()
    
    threads = []
    for i in range(CONCURRENT_USERS):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()

    # Wait for all threads to finish
    for t in threads:
        t.join()

    duration = time.time() - start_time
    rps = TOTAL_REQUESTS / duration

    print(f"\n\n{'-'*40}")
    print(f"✅ Test Complete in {duration:.2f} seconds")
    print(f"⚡ Average RPS: {rps:.2f}")
    print(f"🟢 Successful Requests: {success_count}")
    print(f"🔴 Failed/Refused: {error_count}")

if __name__ == "__main__":
    # Simple check if server is up before blasting
    try:
        requests.get(TARGET_URL, timeout=2)
    except:
        print(f"❌ Could not connect to {TARGET_URL}. Is your server running?")
        sys.exit(1)
        
    run_test()
