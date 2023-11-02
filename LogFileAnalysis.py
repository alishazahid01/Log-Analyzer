# Log File analysis
import re

def log_file_analysis(file_path, suspicious_words, log_entry_pattern, suspicious_activity):
    suspicious_count = 0

    # Read log file
    with open(file_path, 'r') as file:
        # Read each line of the file
        for line in file:
            # Log pattern matches
            try:
                # Attempt to match log entry pattern
                match = re.search(log_entry_pattern, line)
                
                if match:
                    date_and_time = match.group(1)
                    activity_type = match.group(2)
                    message = match.group(3)

                    for word in suspicious_words:
                        if re.search(word, message, re.IGNORECASE):
                            print("Suspicious activity found.....")
                            suspicious_count += 1
                            suspicious_activity.append((date_and_time, activity_type, message))
                            write_in_file(date_and_time, activity_type, message)

            except AttributeError:
                print("Error Found...")
                continue

    return suspicious_count

def write_in_file(date_and_time, activity_type, message):
    with open("suspicious_activities.txt", 'a') as file:
        file.write(f"Timestamp: {date_and_time}, Activity Type: {activity_type}, Message: {message}\n")

if __name__ == "__main__":
    suspicious_activity = []

    # Prompt user to enter path of the log file
    file_path = input("Enter the path of the log file: ")

    suspicious_words = ['Unauthorized', 'SQL injections', 'Malicious payload detected', 'Address not available', 'Operation not supported on socket']
    log_entry_pattern = r'(\d{2}/\d{2} \d{2}:\d{2}:\d{2}) ([A-Z]+) +:?(.*?)$'


    suspicious_message_count = log_file_analysis(file_path, suspicious_words, log_entry_pattern, suspicious_activity)

    print(f"Number of suspicious messages found: {suspicious_message_count}")
