# customer_login
from collections import defaultdict

# Path to the uploaded log file in Colab (change this to your file's name if needed)
file_name = '/content/server_logs.txt'

# Function to parse the log file and extract information
def parse_log(file_path):
    failed_attempts_by_customer = defaultdict(lambda: defaultdict(int))  # customer -> ip -> count
    successful_attempts = 0
    failed_attempts = 0

    # Open the file and read its contents
    with open(file_path, 'r') as file:
        logs = file.readlines()

        # Process each log line
        for log in logs:
            try:
                parts = log.strip().split(" - ")
                if len(parts) < 2:
                    continue  # Skip lines that don't have the correct format

                timestamp = parts[0]
                status, details = parts[1].split(" from ")
                ip_address = details.split(" for ")[0].strip()
                customer_id = details.split(" for ")[1].split(":")[1].strip()

                if 'Failed' in status:
                    failed_attempts += 1
                    failed_attempts_by_customer[customer_id][ip_address] += 1
                elif 'Successful' in status:
                    successful_attempts += 1

            except Exception as e:
                print(f"Error processing log line: {log.strip()} | Error: {e}")
                continue  # Skip lines that can't be processed

    return failed_attempts, successful_attempts, failed_attempts_by_customer

# Function to check for suspicious activity based on the failed login attempts
def check_suspicious_activity(failed_attempts_by_customer):
    suspicious_customers = {}

    for customer_id, ip_data in failed_attempts_by_customer.items():
        total_failed_attempts = sum(ip_data.values())
        if total_failed_attempts >= 3:  # Flag if failed attempts are 3 or more from the same or different IPs
            suspicious_customers[customer_id] = ip_data

    return suspicious_customers

# Main function to run the analysis
def main():
    # Path to your uploaded log file in Colab
    file_path = file_name  # This is where your uploaded file will be

    failed_attempts, successful_attempts, failed_attempts_by_customer = parse_log(file_path)

    # Display the results
    print(f"Total Failed Login Attempts: {failed_attempts}")
    print(f"Total Successful Login Attempts: {successful_attempts}")

    # Check for suspicious activity
    suspicious_customers = check_suspicious_activity(failed_attempts_by_customer)

    print("\nCustomers with 3 or More Failed Login Attempts:")
    for customer, ip_data in suspicious_customers.items():
        print(f"Customer ID: {customer}")
        total_failed_attempts = sum(ip_data.values())
        print(f"Number of Failed Login Attempts: {total_failed_attempts}")
        print(f"IP Addresses Attempted: {', '.join(ip_data.keys())}")
        print()  # Add a one-line space between different customer IDs

# Run the analysis
if __name__ == "__main__":
    main()
