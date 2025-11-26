#!/bin/bash
echo "Starting AI Anomaly Detection System..."
docker-compose up -d
sleep 10
pip install scikit-learn numpy
python src/anomaly_detector.py
