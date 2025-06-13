import psutil
import socket
import threading
import logging
import time
from typing import Set, Dict
import ipaddress

class NetworkInterfaceMonitor:
    def __init__(self):
        self.active_interfaces: Set[str] = set()
        self.interface_ips: Dict[str, str] = {}
        self.logger = logging.getLogger(__name__)
        self._stop_event = threading.Event()
        
    def get_active_interfaces(self) -> Set[str]:
        """Récupère les interfaces réseau actives avec IP valide"""
        active_interfaces = set()
        interface_ips = {}
        
        # Récupère toutes les adresses IP de toutes les interfaces
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    ip = addr.address
                    try:
                        # Vérifie si l'IP est valide et non réservée
                        ip_obj = ipaddress.ip_address(ip)
                        if not ip_obj.is_loopback and not ip_obj.is_link_local:
                            active_interfaces.add(interface)
                            interface_ips[interface] = ip
                    except ValueError:
                        continue
        
        self.active_interfaces = active_interfaces
        self.interface_ips = interface_ips
        return active_interfaces

    def start_monitoring(self, callback=None, interval=5):
        """Démarre le monitoring des interfaces réseau
        
        Args:
            callback: Fonction à appeler quand une nouvelle interface devient active
            interval: Intervalle de vérification en secondes
        """
        def monitor_thread():
            while not self._stop_event.is_set():
                try:
                    current_interfaces = self.get_active_interfaces()
                    
                    # Vérifie si de nouvelles interfaces sont apparues
                    new_interfaces = current_interfaces - self.active_interfaces
                    if new_interfaces:
                        self.logger.info(f"Nouvelles interfaces détectées: {new_interfaces}")
                        if callback:
                            for interface in new_interfaces:
                                callback(interface, self.interface_ips[interface])
                    
                    time.sleep(interval)
                except Exception as e:
                    self.logger.error(f"Erreur lors du monitoring: {e}")
                    time.sleep(interval)
        
        self.monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Monitoring des interfaces réseau démarré")

    def stop(self):
        """Arrête le monitoring des interfaces"""
        self._stop_event.set()
        if hasattr(self, 'monitor_thread') and self.monitor_thread.is_alive():
            self.monitor_thread.join()
        self.logger.info("Monitoring des interfaces arrêté")
