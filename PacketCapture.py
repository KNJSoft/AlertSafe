from scapy.all import sniff
from collections import defaultdict
import threading
import queue
from scapy.layers.inet import IP, TCP
import logging

class PacketCapture:
    def __init__(self, max_queue_size=1000):
        self.packet_queue = queue.Queue(maxsize=max_queue_size)
        self.stop_capture = threading.Event()
        self.interface = None
        self.logger = logging.getLogger(__name__)

    def packet_callback(self, packet):
        try:
            if IP in packet and TCP in packet:
                self.packet_queue.put_nowait(packet)
        except queue.Full:
            self.logger.warning("Queue pleine, paquet ignoré")

    def start_capture(self, interface="auto"):
        try:
            if interface == "auto":
                # Use a common default interface
                interface = "wlp2s0"  # Common wireless interface name on Linux
            self.interface = interface
            def capture_thread():
                try:
                    sniff(iface=self.interface,
                          prn=self.packet_callback,
                          store=0,
                          stop_filter=lambda _: self.stop_capture.is_set())
                except Exception as e:
                    self.logger.error(f"Erreur lors de la capture : {e}")
                    self.stop_capture.set()

            self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
            self.capture_thread.start()
            self.logger.info(f"Capture démarrée sur {self.interface}")
        except Exception as e:
            self.logger.error(f"Erreur lors du démarrage de la capture : {e}")
            raise

    def stop(self):
        self.stop_capture.set()
        if hasattr(self, 'capture_thread') and self.capture_thread.is_alive():
            self.capture_thread.join()
            self.logger.info("Capture arrêtée")


class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        flow_duration = stats['last_time'] - stats['start_time']
        packet_rate = 0
        byte_rate = 0
        if flow_duration > 0:
            packet_rate = stats['packet_count'] / flow_duration
            byte_rate = stats['byte_count'] / flow_duration
        return {
            'packet_size': len(packet),
            'flow_duration': stats['last_time'] - stats['start_time'],
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }

