#!/bin/bash
# Start script for GEN WAF (Binary)
# Usage: ./scripts/start.sh

# Navigate to the root of the release folder
cd "$(dirname "$0")/.."
mkdir -p logs

# 1. Validate configuration
echo "Validating configuration..."
./bin/genctl validate -config config/genwaf.yaml
if [ $? -ne 0 ]; then
    echo "Configuration validation failed! Please check config/genwaf.yaml"
    exit 1
fi

# 2. Compile configuration for Data Plane (Sync)
echo "Syncing configuration..."
./bin/genctl compile -config config/genwaf.yaml -output config/effective.json
if [ $? -ne 0 ]; then
    echo "Configuration compilation failed!"
    exit 1
fi

# 3. Start Data Plane (gendp)
echo "Starting Data Plane (gendp)..."
nohup ./bin/gendp --config config/effective.json > logs/gendp.log 2>&1 &
GENDP_PID=$!

# 4. Start Control Plane (genctl)
echo "Starting Control Plane (genctl)..."
nohup ./bin/genctl serve --config config/genwaf.yaml -listen :8080 > logs/genctl.log 2>&1 &
GENCTL_PID=$!

echo "GEN WAF started successfully!"
echo "   - Data Plane PID: $GENDP_PID"
echo "   - Control Plane PID: $GENCTL_PID"
echo "   - Dashboard: http://127.0.0.1:8080/dashboard"
echo "   - View logs in the logs/ directory."
