import pytest
from NetworkInterfaceMonitor import NetworkInterfaceMonitor

def test_network_interface_detection():
    """Test que le NetworkInterfaceMonitor peut détecter des interfaces réseau"""
    monitor = NetworkInterfaceMonitor()
    interfaces = monitor.get_active_interfaces()
    
    # Vérifier qu'au moins une interface est détectée
    assert len(interfaces) > 0, "Aucune interface réseau détectée"
    
    # Vérifier que chaque interface a une adresse IP valide
    for interface in interfaces:
        assert interface in monitor.interface_ips, f"Pas d'adresse IP pour l'interface {interface}"
        ip = monitor.interface_ips[interface]
        assert ip is not None, f"Adresse IP None pour l'interface {interface}"

def test_network_monitor_start_stop():
    """Test le démarrage et l'arrêt du monitoring des interfaces"""
    monitor = NetworkInterfaceMonitor()
    
    # Créer un callback de test
    test_callback_called = False
    def test_callback(interface, ip):
        nonlocal test_callback_called
        test_callback_called = True
    
    # Démarrer le monitoring
    monitor.start_monitoring(callback=test_callback)
    
    # Vérifier que le thread de monitoring est démarré
    assert hasattr(monitor, 'monitor_thread'), "Le thread de monitoring n'a pas été créé"
    assert monitor.monitor_thread.is_alive(), "Le thread de monitoring n'est pas actif"
    
    # Arrêter le monitoring
    monitor.stop()
    
    # Vérifier que le thread est arrêté
    assert not monitor.monitor_thread.is_alive(), "Le thread de monitoring n'a pas été arrêté correctement"
