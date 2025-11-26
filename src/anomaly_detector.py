#!/usr/bin/env python3
"""
AI-Powered Anomaly Detection System
"""

import psycopg2
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class AnomalyDetector:
    
    def __init__(self):
        self.conn = None
        self.model = None
        
    def connect(self):
        try:
            self.conn = psycopg2.connect(
                host='localhost',
                port=5448,
                dbname='anomaly_db',
                user='postgres',
                password='postgres'
            )
            self.conn.autocommit = True
            logger.info("Connected to database")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def setup(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS db_metrics (
                metric_id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT NOW(),
                query_latency_ms DECIMAL(10,2),
                connections_active INT,
                cpu_usage DECIMAL(5,2),
                memory_usage DECIMAL(5,2),
                disk_io_rate DECIMAL(10,2),
                transaction_rate INT
            );
            
            CREATE TABLE IF NOT EXISTS detected_anomalies (
                anomaly_id SERIAL PRIMARY KEY,
                detected_at TIMESTAMP DEFAULT NOW(),
                metric_name VARCHAR(100),
                metric_value DECIMAL(15,2),
                anomaly_score DECIMAL(10,4),
                severity VARCHAR(20),
                description TEXT
            );
        """)
        cursor.close()
        logger.info("Tables initialized")
    
    def generate_normal_metrics(self, count: int = 100):
        logger.info(f"Generating {count} normal metric samples...")
        
        cursor = self.conn.cursor()
        
        for i in range(count):
            query_latency = np.random.normal(50, 10)
            connections = np.random.randint(20, 50)
            cpu_usage = np.random.normal(40, 10)
            memory_usage = np.random.normal(60, 15)
            disk_io = np.random.normal(100, 20)
            txn_rate = np.random.randint(800, 1200)
            
            cursor.execute("""
                INSERT INTO db_metrics 
                (query_latency_ms, connections_active, cpu_usage, 
                 memory_usage, disk_io_rate, transaction_rate)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (float(query_latency), int(connections), float(cpu_usage), 
                  float(memory_usage), float(disk_io), int(txn_rate)))
        
        cursor.close()
        logger.info("Normal metrics generated")
    
    def inject_anomalies(self):
        logger.info("Injecting anomalous metrics...")
        
        cursor = self.conn.cursor()
        
        anomalies = [
            (500, 35, 45, 65, 110, 1000),
            (55, 150, 75, 80, 200, 1100),
            (60, 40, 50, 95, 120, 900),
            (200, 45, 60, 70, 1000, 500)
        ]
        
        for anomaly in anomalies:
            cursor.execute("""
                INSERT INTO db_metrics 
                (query_latency_ms, connections_active, cpu_usage, 
                 memory_usage, disk_io_rate, transaction_rate)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, anomaly)
        
        cursor.close()
        logger.info(f"Injected {len(anomalies)} anomalous patterns")
    
    def train_model(self):
        logger.info("Training anomaly detection model...")
        
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT query_latency_ms, connections_active, cpu_usage,
                   memory_usage, disk_io_rate, transaction_rate
            FROM db_metrics
            ORDER BY metric_id
        """)
        
        data = np.array(cursor.fetchall())
        cursor.close()
        
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        self.model.fit(data)
        
        logger.info("Model trained successfully")
    
    def detect_anomalies(self):
        logger.info("Scanning for anomalies...")
        
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT metric_id, timestamp, query_latency_ms, connections_active,
                   cpu_usage, memory_usage, disk_io_rate, transaction_rate
            FROM db_metrics
            ORDER BY metric_id DESC
            LIMIT 50
        """)
        
        metrics = cursor.fetchall()
        anomalies_found = []
        
        for metric in metrics:
            metric_id, timestamp, latency, conns, cpu, mem, disk_io, txn_rate = metric
            
            features = np.array([[latency, conns, cpu, mem, disk_io, txn_rate]])
            prediction = self.model.predict(features)
            anomaly_score = self.model.score_samples(features)[0]
            
            if prediction[0] == -1:
                anomalous_metric, value, severity = self._identify_anomaly(
                    latency, conns, cpu, mem, disk_io, txn_rate
                )
                
                anomaly_data = {
                    'metric_id': metric_id,
                    'timestamp': timestamp,
                    'metric_name': anomalous_metric,
                    'value': value,
                    'anomaly_score': abs(float(anomaly_score)),
                    'severity': severity
                }
                
                anomalies_found.append(anomaly_data)
                
                cursor.execute("""
                    INSERT INTO detected_anomalies
                    (metric_name, metric_value, anomaly_score, severity, description)
                    VALUES (%s, %s, %s, %s, %s)
                """, (str(anomalous_metric), float(value), float(abs(anomaly_score)), 
                      str(severity), f"Unusual {anomalous_metric} detected"))
        
        cursor.close()
        logger.info(f"Found {len(anomalies_found)} anomalies")
        return anomalies_found
    
    def _identify_anomaly(self, latency, conns, cpu, mem, disk_io, txn_rate):
        thresholds = {
            'query_latency_ms': (30, 70, latency),
            'connections_active': (15, 60, conns),
            'cpu_usage': (20, 60, cpu),
            'memory_usage': (40, 80, mem),
            'disk_io_rate': (70, 130, disk_io),
            'transaction_rate': (700, 1300, txn_rate)
        }
        
        max_deviation = 0
        anomalous_metric = 'unknown'
        anomalous_value = 0
        
        for metric_name, (low, high, value) in thresholds.items():
            if value < low:
                deviation = (low - value) / low
                if deviation > max_deviation:
                    max_deviation = deviation
                    anomalous_metric = metric_name
                    anomalous_value = value
            elif value > high:
                deviation = (value - high) / high
                if deviation > max_deviation:
                    max_deviation = deviation
                    anomalous_metric = metric_name
                    anomalous_value = value
        
        if max_deviation > 2.0:
            severity = 'critical'
        elif max_deviation > 1.0:
            severity = 'high'
        else:
            severity = 'medium'
        
        return anomalous_metric, anomalous_value, severity
    
    def print_anomaly_report(self, anomalies):
        print("\n" + "=" * 80)
        print("AI ANOMALY DETECTION REPORT")
        print("=" * 80)
        print(f"Scan Time: {datetime.now()}")
        print(f"Total Anomalies Detected: {len(anomalies)}")
        
        if not anomalies:
            print("\nNo anomalies detected")
        else:
            critical = [a for a in anomalies if a['severity'] == 'critical']
            high = [a for a in anomalies if a['severity'] == 'high']
            medium = [a for a in anomalies if a['severity'] == 'medium']
            
            print(f"\nSeverity Breakdown:")
            print(f"  Critical: {len(critical)}")
            print(f"  High: {len(high)}")
            print(f"  Medium: {len(medium)}")
            
            print("\nDetailed Anomalies:")
            for i, anomaly in enumerate(anomalies, 1):
                print(f"\n  [{i}] Anomaly Detected")
                print(f"      Time: {anomaly['timestamp']}")
                print(f"      Metric: {anomaly['metric_name']}")
                print(f"      Value: {anomaly['value']:.2f}")
                print(f"      Score: {anomaly['anomaly_score']:.4f}")
                print(f"      Severity: {anomaly['severity'].upper()}")
        
        print("=" * 80)
    
    def run_demo(self):
        print("\n" + "=" * 80)
        print("AI-POWERED ANOMALY DETECTION SYSTEM")
        print("=" * 80)
        
        if not self.connect():
            return
        
        self.setup()
        
        print("\nPHASE 1: Generate Normal Baseline")
        print("-" * 80)
        self.generate_normal_metrics(100)
        
        print("\nPHASE 2: Train ML Model")
        print("-" * 80)
        self.train_model()
        
        print("\nPHASE 3: Inject Anomalous Patterns")
        print("-" * 80)
        self.inject_anomalies()
        
        print("\nPHASE 4: Detect Anomalies")
        print("-" * 80)
        anomalies = self.detect_anomalies()
        self.print_anomaly_report(anomalies)
        
        print("\n" + "=" * 80)
        print("Key Features:")
        print("  - ML-based detection (Isolation Forest)")
        print("  - Automatic severity classification")
        print("  - Multi-metric analysis")
        print("=" * 80)


def main():
    detector = AnomalyDetector()
    detector.run_demo()


if __name__ == "__main__":
    main()
