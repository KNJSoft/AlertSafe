import queue
import numpy as np
import json  # Importez le module json

from scapy.layers.inet import IP, TCP

from AlertSystem import AlertSystem
from DetectionEngine import DetectionEngine
from PacketCapture import PacketCapture, TrafficAnalyzer


class IntrusionDetectionSystem:
    def __init__(self, interface="wlp2s0"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        self.interface = interface

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        # Entraîner le modèle de détection d'anomalies
        # Exemple : Entraîner avec les 100 premiers paquets capturés comme trafic normal
        normal_traffic_data = []
        for _ in range(100):  # Nombre arbitraire, ajuster selon tes besoins
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    normal_traffic_data.append(list(features.values()))  # Convertir en liste de valeurs
            except queue.Empty:
                print("Queue vide pendant l'entraînement initial.")
                break  # Sortir de la boucle si la queue est vide
        if normal_traffic_data:
            self.detection_engine.train_anomaly_detector(np.array(normal_traffic_data))
        else:
            print("Aucune donnée normale capturée pour entraîner le modèle d'anomalie.")

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)

                    for threat in threats:
                        # Convertir packet[TCP].flags en une représentation JSON sérialisable
                        tcp_flags_str = str(packet[TCP].flags) if TCP in packet else "No TCP"
                        packet_info = {
                            'source_ip': packet[IP].src if IP in packet else "No IP",
                            'destination_ip': packet[IP].dst if IP in packet else "No IP",
                            'source_port': packet[TCP].sport if TCP in packet else 0,
                            'destination_port': packet[TCP].dport if TCP in packet else 0,
                            'tcp_flags': tcp_flags_str,  # Utiliser la chaîne ici
                        }
                        self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capture.stop()
                break


if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("Error: This script must be run with root privileges to capture network packets")
        print("Please run with sudo: sudo python3 main.py")
        exit(1)
    
    ids = IntrusionDetectionSystem()
    ids.start()
