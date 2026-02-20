#!/bin/bash
IMAGE_NAME=honeypot_target:latest
docker build -t $IMAGE_NAME -f Dockerfile.target .
echo "Built image: $IMAGE_NAME"
