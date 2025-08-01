import logging
import json
from datetime import datetime
from scapy.packet import Packet
from scapy.fields import FlagValue

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'interface': threat.get('interface', 'unknown'),
            'details': threat
        }

        class ScapyJSONEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, FlagValue):
                    return str(obj)
                if isinstance(obj, Packet):
                    return str(obj)
                return super().default(obj)

        self.logger.warning(json.dumps(alert, cls=ScapyJSONEncoder))

        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )
            # Implement additional notification methods here
            # (e.g., email, Slack, SIEM integration)
