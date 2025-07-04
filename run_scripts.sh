#!/bin/bash

# Run main.py at the top of every hour
while true; do
    current_minute=$(date +%M)
    if [ "$current_minute" -eq 0 ]; then
        /usr/bin/python3 /home/alex/cve_monitor/main.py
    fi
    sleep 60
done &

# Run app.py at 20 minutes past every hour
while true; do
    current_minute=$(date +%M)
    if [ "$current_minute" -eq 20 ]; then
        /usr/bin/python3 /home/alex/cve_monitor/app.py
    fi
    sleep 60
done &

# Run check.py at 30 minutes past every hour
while true; do
    current_minute=$(date +%M)
    if [ "$current_minute" -eq 30 ]; then
        /usr/bin/python3 /home/alex/cve_monitor/check.py
    fi
    sleep 60
done &

# Wait for all background jobs to finish
wait
