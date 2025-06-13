from collections import defaultdict
import time
import logging
from scapy.layers.inet import IP, TCP

class TrafficAnalyzer:
    def __init__(self, max_connections=10000, idle_timeout=300):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'last_activity': time.time()
        })
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self.logger = logging.getLogger(__name__)

    def cleanup_idle_connections(self):
        """Supprime les connexions inactives."""
        current_time = time.time()
        keys_to_remove = []
        
        for flow_key in self.flow_stats:
            if current_time - self.flow_stats[flow_key]['last_activity'] > self.idle_timeout:
                keys_to_remove.append(flow_key)
        
        for key in keys_to_remove:
            del self.flow_stats[key]
            del self.connections[key]
            self.logger.debug(f"Connexion inutilisée nettoyée: {key}")

    def analyze_packet(self, packet):
        try:
            if IP in packet and TCP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                port_src = packet[TCP].sport
                port_dst = packet[TCP].dport

                flow_key = (ip_src, ip_dst, port_src, port_dst)

                # Nettoyer les connexions inactives périodiquement
                if len(self.flow_stats) > self.max_connections * 0.8:
                    self.cleanup_idle_connections()

                # Mettre à jour les statistiques de flux
                stats = self.flow_stats[flow_key]
                stats['packet_count'] += 1
                stats['byte_count'] += len(packet)
                current_time = packet.time

                if not stats['start_time']:
                    stats['start_time'] = current_time
                stats['last_time'] = current_time
                stats['last_activity'] = current_time

                return self.extract_features(packet, stats)
            return None
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse du paquet: {e}")
            return None

    def extract_features(self, packet, stats):
        try:
            flow_duration = stats['last_time'] - stats['start_time']
            packet_rate = 0
            byte_rate = 0
            
            if flow_duration > 0:
                packet_rate = stats['packet_count'] / flow_duration
                byte_rate = stats['byte_count'] / flow_duration
                
            # Convertir les flags TCP en entier
            tcp_flags_value = 0
            if isinstance(packet[TCP].flags, int):
                tcp_flags_value = packet[TCP].flags
            else:
                tcp_flags_value = int(packet[TCP].flags)

            return {
                'packet_size': len(packet),
                'flow_duration': flow_duration,
                'packet_rate': packet_rate,
                'byte_rate': byte_rate,
                'tcp_flags': tcp_flags_value,
                'window_size': packet[TCP].window,
                'protocol': packet[IP].proto
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de l'extraction des fonctionnalités: {e}")
            return None
