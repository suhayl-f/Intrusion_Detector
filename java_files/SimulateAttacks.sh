#!/bin/bash

LOG_FILE="logs/auth.log"

echo "=== Starting Live Attack & Traffic Simulation ==="
echo "Make sure 'java Main' is running in another terminal tab!"
sleep 2

echo "[1/5] Sending normal daytime login (Should NOT alert)..."
echo "Nov 24 14:10:00 prod-web-01 sshd: Accepted password for devuser from 10.0.0.15 port 51200 ssh2" >> $LOG_FILE
sleep 2

echo "[2/5] Sending off-hours login at 03:15 AM (Should trigger MEDIUM alert)..."
echo "Nov 24 03:15:00 prod-web-01 sshd: Accepted password for jsmith from 172.16.0.88 port 51201 ssh2" >> $LOG_FILE
sleep 2

echo "[3/5] Simulating 5-attempt SSH brute-force attack (Should trigger HIGH alert once)..."
for i in {1..5}; do
    echo "Nov 24 14:12:0$i prod-web-01 sshd: Failed password for admin from 203.0.113.99 port 4400$i ssh2" >> $LOG_FILE
    sleep 0.5
done
sleep 2

echo "[4/5] Simulating direct root login attempt (Should trigger MEDIUM alert)..."
echo "Nov 24 14:15:00 prod-web-01 sshd: Failed password for root from 198.51.100.77 port 33210 ssh2" >> $LOG_FILE
sleep 2

echo "[5/5] Simulating successful compromise after failed attempts (Should trigger CRITICAL alert)..."
echo "Nov 24 14:16:01 prod-web-01 sshd: Failed password for deploy from 185.220.101.9 port 60101 ssh2" >> $LOG_FILE
sleep 0.5
echo "Nov 24 14:16:03 prod-web-01 sshd: Failed password for deploy from 185.220.101.9 port 60102 ssh2" >> $LOG_FILE
sleep 0.5
echo "Nov 24 14:16:05 prod-web-01 sshd: Accepted password for deploy from 185.220.101.9 port 60103 ssh2" >> $LOG_FILE

echo "=== Simulation Complete! Check your Java terminal and alerts.json ==="
