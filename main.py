import queue
import numpy as np
import json  # Importez le module json

from scapy.layers.inet import IP, TCP

from AlertSystem import AlertSystem
from DetectionEngine import DetectionEngine
from PacketCapture import PacketCapture, TrafficAnalyzer
from NetworkInterfaceMonitor import NetworkInterfaceMonitor


class IntrusionDetectionSystem:
    def __init__(self):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.active_interfaces = set()
        self.interface_monitor = NetworkInterfaceMonitor()
        self.interface_monitor.start_monitoring(self._handle_new_interface)

    def _handle_new_interface(self, interface, ip):
        """Gère l'ajout d'une nouvelle interface active"""
        if interface not in self.active_interfaces:
            print(f"Nouvelle interface détectée: {interface} ({ip})")
            self.active_interfaces.add(interface)
            # Démarrer la capture sur la nouvelle interface
            self.packet_capture.start_capture(interface)

    def start(self):
        print("Starting IDS...")
        # D'abord récupérer les interfaces actives
        active_interfaces = self.interface_monitor.get_active_interfaces()
        print(f"Interfaces actives détectées: {active_interfaces}")
        
        # Démarrer la capture sur toutes les interfaces actives
        for interface in active_interfaces:
            self._handle_new_interface(interface, self.interface_monitor.interface_ips[interface])

        # Entraîner le modèle de détection d'anomalies
        normal_traffic_data = []
        for _ in range(100):  # Nombre arbitraire, ajuster selon tes besoins
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    # Ajouter les features comme un dictionnaire
                    normal_traffic_data.append(features)
            except queue.Empty:
                print("Queue vide pendant l'entraînement initial.")
                break  # Sortir de la boucle si la queue est vide
        if normal_traffic_data:
            # Pas besoin de conversion numpy ici, DetectionEngine s'en occupe
            self.detection_engine.train_anomaly_detector(normal_traffic_data)
        else:
            print("Aucune donnée normale capturée pour entraîner le modèle d'anomalie.")

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features, interface)

                    for threat in threats:
                        # Convertir packet[TCP].flags en une représentation JSON sérialisable
                        tcp_flags_str = str(packet[TCP].flags) if TCP in packet else "No TCP"
                        packet_info = {
                            'source_ip': packet[IP].src if IP in packet else "No IP",
                            'destination_ip': packet[IP].dst if IP in packet else "No IP",
                            'source_port': packet[TCP].sport if TCP in packet else 0,
                            'destination_port': packet[TCP].dport if TCP in packet else 0,
                            'tcp_flags': tcp_flags_str,
                            'interface': interface
                        }
                        self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.interface_monitor.stop()
                self.packet_capture.stop()
                break




if __name__ == "__main__":
    import os
    import logging
    
    # Configurer le logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    if os.geteuid() != 0:
        print("Error: This script must be run with root privileges to capture network packets")
        print("Please run with sudo: sudo python3 main.py")
        exit(1)
    
    ids = IntrusionDetectionSystem()
    ids.start()
