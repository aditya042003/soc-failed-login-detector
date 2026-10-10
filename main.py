from collections import defaultdict

file_path = "logs/login_logs.txt"

# Read login records
with open(file_path, "r") as file:
    logs = file.readlines()

# Store failed attempts by IP
ip_counts = defaultdict(int)

print("=" * 55)
print("         SOC FAILED LOGIN DETECTOR")
print("=" * 55)

print("\nFAILED LOGIN DETAILS")
print("-" * 55)

# Read and display failed login records
for log in logs:
    parts = log.strip().split(" | ")

    if len(parts) != 4:
        continue

    timestamp, username, ip_address, status = parts

    if status == "FAILED":
        ip_counts[ip_address] += 1

        print("Time     :", timestamp)
        print("Username :", username)
        print("IP Address:", ip_address)
        print("-" * 55)

# Display total failed attempts
total_failed = sum(ip_counts.values())

print("\nTotal failed attempts:", total_failed)

# Generate suspicious IP alerts
print("\nSECURITY ALERTS")
print("-" * 55)

alert_found = False

for ip_address, count in ip_counts.items():
    if count >= 5:
        alert_found = True
        print("ALERT: Suspicious IP detected:", ip_address)
        print("Failed attempts from this IP:", count)

if not alert_found:
    print("No suspicious IP detected.")

print("\nAnalysis completed.")