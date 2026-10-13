import pandas as pd

#import pandas as pd

while True:
    print("\n====================================")
    print(" CYBERSECURITY LOG ANALYSIS SYSTEM")
    print("====================================")
    print("1. View all security logs")
    print("2. Analyse login attempts")
    print("3. Identify suspicious activity")
    print("4. Exit")

    choice = input("Enter your choice (1-4): ").strip()

    if choice == "1":
        print("Viewing all security logs...")
    elif choice == "2":
        print("Analysing login attempts...")
    elif choice == "3":
        print("Identifying suspicious activity...")
    elif choice == "4":
        print("System closed. Goodbye!")
        break
    else:
        print("Invalid choice. Please enter 1, 2, 3 or 4.")
import csv
from collections import Counter

def analyse_login_attempts():
    successful = 0
    failed = 0

    try:
        with open("security_logs.csv", "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            for row in reader:
                status = row.get("status", "").strip().lower()

                if status in ("success", "successful", "successfully"):
                    successful += 1
                elif status in ("failed", "failure", "unsuccessful"):
                    failed += 1

        print("\n--- Login Analysis ---")
        print(f"Successful logins: {successful}")
        print(f"Failed logins: {failed}")

    except FileNotFoundError:
        print("Error: security_logs.csv was not found.")
def identify_suspicious_activity():
    failed_attempts = Counter()

    try:
        with open("security_logs.csv", "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            for row in reader:
                values = [str(value).strip().lower() for value in row.values()]

                is_failed = any(
                    word in value
                    for value in values
                    for word in ("failed", "failure", "unsuccessful")
                )

                if is_failed:
                    ip_address = (
                        row.get("ip_address")
                        or row.get("ip")
                        or row.get("source_ip")
                        or "Unknown IP"
                    )
                    failed_attempts[ip_address] += 1

        print("\n===== SUSPICIOUS ACTIVITY =====")

        found = False

        for ip, count in failed_attempts.items():
            if count >= 3:
                print(f"WARNING: {ip} has {count} failed attempts.")
                found = True

        if not found:
            print("No IP addresses with 3 or more failed attempts found.")

    except FileNotFoundError:
        print("Error: security_logs.csv was not found.")
    