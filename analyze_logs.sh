#!/bin/bash

LOG_FILE=${1:-app.log}

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Log file $LOG_FILE does not exist."
    echo "Please provide the correct log file as the first argument."
    exit 1
fi

echo "Log Analysis Report"
echo "File: $LOG_FILE"
echo "Date: $(date)"
echo

echo "Failed Login Analysis"
echo "Top 10 Failed Login Attempts:"
grep "Login failed" "$LOG_FILE" | awk -F'for ' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -nr | head -10

echo
echo "Registration Issues"
echo "Top 10 Registration Errors:"
grep "Registration error" "$LOG_FILE" | awk -F'Registration error for ' '{print $2}' | awk -F: '{print $1}' | sort | uniq -c | sort -nr | head -10

echo
echo "Profile Update Issues"
echo "Top 10 Profile Update Errors:"
grep "Profile update error" "$LOG_FILE" | awk -F'for ' '{print $2}' | awk -F: '{print $1}' | sort | uniq -c | sort -nr | head -10

echo
echo "Error Analysis"
echo "404 Not Found Errors (Top 10):"
grep "404 Not Found" "$LOG_FILE" | awk -F': ' '{print $2}' | sort | uniq -c | sort -nr | head -10

echo
echo "Rate Limiting (429) Errors (Top 10):"
grep "429 Too Many Requests" "$LOG_FILE" | awk -F': ' '{print $2}' | sort | uniq -c | sort -nr | head -10

echo
echo "Summary Statistics:"
echo "Total Failed Logins: $(grep -c 'Login failed' "$LOG_FILE")"
echo "Total Registration Errors: $(grep -c 'Registration error' "$LOG_FILE")"
echo "Total Profile Update Errors: $(grep -c 'Profile update error' "$LOG_FILE")"
echo "Total 404 Errors: $(grep -c '404 Not Found' "$LOG_FILE")"
echo "Total 429 Errors: $(grep -c '429 Too Many Requests' "$LOG_FILE")" 