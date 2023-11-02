# Log-Analyzer
Overview
The "Log File Analysis" script is a powerful tool designed to analyze log files and automatically detect suspicious activities. This documentation provides an in-depth understanding of the script's purpose, its inner workings, and how to make the most of it.

Purpose
Log files generated by applications and systems often contain valuable insights into system behavior and potential security threats. The primary purpose of this script is to automate the process of analyzing log files and flagging entries that match predefined patterns and keywords, helping you identify potential security breaches and suspicious activities.

Code Structure and Functionality
Imported Libraries
The script utilizes the re library for regular expressions, which is crucial for pattern matching within log entries.

log_file_analysis Function
This function is the heart of the script, and it does the heavy lifting. Here's how it works:

Parameters:

file_path: The path to the log file you want to analyze.
suspicious_words: A list of suspicious keywords to search for in log entries.
log_entry_pattern: A regular expression pattern to match log entries.
suspicious_activity: A list used to store suspicious log entries.
How it operates:

The function reads the log file line by line and attempts to match each line with the specified log_entry_pattern.
When a match is found, it extracts the date and time, activity type, and message from the log entry.
It then checks if any of the suspicious_words appear in the log message, ignoring case. If a match is found, the entry is considered suspicious.
If a suspicious entry is found, it is printed to the console, and the information is appended to the suspicious_activity list.
Additionally, the suspicious entry is written to a file named "suspicious_activities.txt" using the write_in_file function.
The function returns the total count of suspicious log entries found.
write_in_file Function
This function is responsible for taking the date and time, activity type, and message from a suspicious log entry and writing this information to the "suspicious_activities.txt" file.

Getting Started
To use the script effectively, follow these steps:

Log File Preparation
Ensure you have a log file (e.g., application logs, server logs) that you want to analyze.

Keyword Configuration
Define a list of suspicious_words containing keywords that may indicate suspicious activity. These keywords are used to identify potential threats in log messages.

Regular Expression Pattern
Define a log_entry_pattern to match log entries. Ensure that the pattern captures relevant information, such as date and time, activity type, and message. Customize the pattern to match your log file format.

Execution
Run the script and provide the path to the log file when prompted.

Review Results
The script will analyze the log file, print any suspicious entries to the console, and write them to a "suspicious_activities.txt" file.

Interpretation
Review the "suspicious_activities.txt" file to examine the flagged log entries and investigate potential security threats or anomalies in the log file.

Customization
You may need to customize the script, including the log_entry_pattern, based on the specific log file format you are working with.

Extending Functionality
Depending on your needs, you can extend the script to perform additional actions when suspicious activities are detected, such as sending notifications or alerts.

Please note: Always use this script responsibly and for legitimate and authorized purposes, such as security testing or recovery of forgotten passwords. Unauthorized use of such tools is illegal and unethical.

