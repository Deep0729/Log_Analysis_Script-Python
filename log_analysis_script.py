import re
import csv
from collections import defaultdict

# This is Configuration
LOG_FILE_PATH = "sample.log"
OUTPUT_CSV_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 1         # Sets a limit to detect suspicious activities

# Process the log file
def process_log_file(log_path):
    ip_activity = defaultdict(int)
    endpoint_hits = defaultdict(int)
    failed_attempts = defaultdict(int)

    with open(log_path, "r") as log:
        for entry in log:

            # Extract the IP address
            ip_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", entry)
            if ip_match:
                ip = ip_match.group(1)
                ip_activity[ip] += 1

            # Extract the accessed endpoint
            endpoint_match = re.search(r"\"(?:GET|POST|PUT|DELETE) ([^\s]+) HTTP/", entry)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_hits[endpoint] += 1

            # Detect failed login attempts
            if "401" in entry or "Invalid credentials" in entry:
                if ip_match:
                    failed_attempts[ip] += 1

    return ip_activity, endpoint_hits, failed_attempts

# This is Function to analyze IP requests
def summarize_ip_activity(ip_activity):
    sorted_ips = sorted(ip_activity.items(), key=lambda item: item[1], reverse=True)
    print("\nCount Requests per IP Address: ")
    print("IP Address           Request Count")
    print("-" * 40)
    for ip, count in sorted_ips:
        print(f"{ip:<20}    {count}")
    return sorted_ips

# This is Function to find the most accessed endpoint
def find_top_endpoint(endpoint_hits):
    top_endpoint = max(endpoint_hits.items(), key=lambda item: item[1])
    print("\nMost Frequently Accessed Endpoint:")
    print("-" * 40)
    print(f"{top_endpoint[0]}  (Accessed {top_endpoint[1]} times)")
    return top_endpoint

# This is Function to identify suspicious activity
def detect_attempts(failed_attempts):
    flagged_ips = {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}
    print("\nSuspicious Activity Detected:")
    print("-" * 40)
    print("IP Address           Failed Login Attempts")
    for ip, count in flagged_ips.items():
        print(f"{ip:<20} {count}")
    return flagged_ips




# This is Function to save results in CSV file format
def export_results_to_csv(ip_activity, top_endpoint, flagged_ips):
    with open(OUTPUT_CSV_FILE, "w", newline="") as csv_file:
        writer = csv.writer(csv_file)

        # Write IP request counts
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address",  "Request Count"])
        writer.writerows(ip_activity)
        writer.writerow([])

        # Write most accessed endpoint
        writer.writerow(["Most Frequently Accessed Endpoint: "])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(top_endpoint)
        writer.writerow([])

        # Write suspicious activity
        writer.writerow(["Suspicious Activity Detected: "])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in flagged_ips.items():
            writer.writerow([ip, count])

# Main function
def main():
    print("\nStarting log analysis Script...")

    # Process the log file
    ip_activity, endpoint_hits, failed_attempts = process_log_file(LOG_FILE_PATH)

    # Summarize IP activity
    sorted_ip_activity = summarize_ip_activity(ip_activity)

    # Find the most accessed endpoint
    top_endpoint = find_top_endpoint(endpoint_hits)

    # Detect attempts
    flagged_ips = detect_attempts(failed_attempts)

    # Export results to a CSV file
    export_results_to_csv(sorted_ip_activity, top_endpoint, flagged_ips)

    print("\nThe analysis is completed. Results saved to:", OUTPUT_CSV_FILE)
    print("\n")

if __name__ == "__main__":
    main()
