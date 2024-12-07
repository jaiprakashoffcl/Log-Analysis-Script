import csv

def analyze_log(log_file):
    ip_counts = {}
    endpoint_counts = {}
    failed_logins = {}

    with open(log_file, 'r') as f:
        for line in f:
            line_parts = line.split()
            if len(line_parts) >= 7:
                ip_address = line_parts[0]
                endpoint = line_parts[6]
                status_code = line_parts[8]
                ip_counts[ip_address] = ip_counts.get(ip_address, 0) + 1
                endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
                if status_code == '401' and 'Invalid credentials' in line:
                    failed_logins[ip_address] = failed_logins.get(ip_address, 0) + 1

    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    most_accessed_endpoint, max_count = max(endpoint_counts.items(), key=lambda x: x[1])
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count >= 10}
    print("Requests per IP Address:")
    for ip, count in sorted_ip_counts:
        print(f"{ip:20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {max_count} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:20} {count}")
    else:
        print("No suspicious activity detected.")

    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, count in sorted_ip_counts:
            writer.writerow({'IP Address': ip, 'Request Count': count})

        fieldnames = ['Endpoint', 'Access Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({'Endpoint': most_accessed_endpoint, 'Access Count': max_count})

        if suspicious_ips:
            fieldnames = ['IP Address', 'Failed Login Count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for ip, count in suspicious_ips.items():
                writer.writerow({'IP Address': ip, 'Failed Login Count': count})
        else:
            writer = csv.writer(csvfile)
            writer.writerow(['No Suspicious Activity Detected'])

analyze_log('sample.log')
