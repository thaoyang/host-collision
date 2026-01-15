#!/bin/bash

# Check number of parameters
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <sld> <t>"
    exit 1
fi

# Get parameters
SLD=$1
T=$2

# Ensure log1 directory exists
mkdir -p log1

# Run program, redirecting both stdout and stderr
nohup go run hostCollision.go -sld "$SLD" -t "$T" > "log1/$SLD.log" 2>&1 &
echo "Start running: hostCollision.go -sld $SLD -t $T"