#!/bin/sh
set -e

echo "Starting Hardhat node in background..."
npx hardhat node --hostname 0.0.0.0 > /app/hardhat.log 2>&1 &
NODE_PID=$!

echo "Waiting for node on port 8545..."
for i in $(seq 1 30); do
  if nc -z localhost 8545; then
    echo "Hardhat node is READY!"
    break
  fi
  echo "Waiting... ($i/30)"
  sleep 2
done

# Deploy contracts
echo "Deploying smart contracts..."
npx hardhat run scripts/deploy.js --network localhost --no-compile

echo "Deployment complete. Tailing logs..."
tail -f /app/hardhat.log
