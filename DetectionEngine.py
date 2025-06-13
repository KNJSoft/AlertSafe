from sklearn.ensemble import IsolationForest
import numpy as np
import logging
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.is_trained = False
        self.logger = logging.getLogger(__name__)  # Utilise un logger

    def load_signature_rules(self):
        # Exemple de règles avec priorité et description
        return {
            'syn_flood': {
                'priority': 1,
                'description': 'Detects SYN flood attacks',
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and
                    features['packet_rate'] > 100
                ),
                'confidence': 1.0
            },
            'port_scan': {
                'priority': 2,
                'description': 'Detects port scanning activity',
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50
                ),
                'confidence': 0.8  # Moins confiant que SYN flood
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        if normal_traffic_data is None or len(normal_traffic_data) == 0:
            self.logger.warning("Aucune donnée d'entraînement fournie. La détection d'anomalies ne fonctionnera pas.")
            return

        try:
            # Extraire les valeurs numériques des dictionnaires
            features = []
            for feature_dict in normal_traffic_data:
                # Extraire les valeurs numériques dans l'ordre correct
                feature_vector = [
                    float(feature_dict.get('packet_size', 0)),
                    float(feature_dict.get('flow_duration', 0)),
                    float(feature_dict.get('packet_rate', 0)),
                    float(feature_dict.get('byte_rate', 0)),
                    float(feature_dict.get('tcp_flags', 0)),
                    float(feature_dict.get('window_size', 0)),
                    float(feature_dict.get('protocol', 0))
                ]
                features.append(feature_vector)

            if not features:
                self.logger.error("Aucune donnée valide pour l'entraînement")
                return

            # Convertir en numpy array avec dtype explicite
            features_array = np.array(features, dtype=np.float64)
            
            # Normaliser les données
            from sklearn.preprocessing import StandardScaler
            scaler = StandardScaler()
            features_normalized = scaler.fit_transform(features_array)
            
            # Entraîner le modèle
            self.anomaly_detector.fit(features_normalized)
            self.is_trained = True
            self.logger.info("Modèle de détection d'anomalies entraîné avec succès.")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'entraînement du modèle : {e}", exc_info=True)
            raise  # Propager l'exception pour que l'appelant puisse la gérer

    def detect_threats(self, features, packet_capture_interface=None):
        threats = []

        # Vérifier que les fonctionnalités nécessaires sont présentes
        required_features = ['packet_size', 'packet_rate', 'byte_rate', 'tcp_flags']
        if not all(feature in features for feature in required_features):
            self.logger.warning("Features manquants pour la détection")
            return threats

        # Détection basée sur les signatures (triées par priorité)
        sorted_rules = sorted(self.signature_rules.items(), key=lambda item: item[1]['priority'])
        for rule_name, rule_data in sorted_rules:
            try:
                if rule_data['condition'](features):
                    threats.append({
                        'type': 'signature',
                        'rule': rule_name,
                        'description': rule_data['description'],
                        'confidence': rule_data['confidence'],
                        'interface': packet_capture_interface if packet_capture_interface else 'unknown',
                        'details': features
                    })
            except Exception as e:
                self.logger.error(f"Erreur lors de l'évaluation de la règle {rule_name}: {e}")
                continue

        # Détection d'anomalies
        if self.is_trained:
            try:
                # Convertir les features en valeurs numériques
                feature_vector = np.array([[
                    float(features.get('packet_size', 0)),
                    float(features.get('packet_rate', 0)),
                    float(features.get('byte_rate', 0))
                ]], dtype=np.float64)
                
                if feature_vector.size == 0:
                    self.logger.warning("Vector de features vide")
                    return threats

                anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
                if anomaly_score < -0.5:  # Seuil d'anomalie
                    confidence = min(1.0, abs(anomaly_score))
                    threats.append({
                        'type': 'anomaly',
                        'score': anomaly_score,
                        'confidence': confidence,
                        'interface': packet_capture_interface if packet_capture_interface else 'unknown',
                        'details': features
                    })
            except Exception as e:
                self.logger.error(f"Erreur lors de la détection d'anomalies : {e}", exc_info=True)
                return threats  # Ne pas ajouter de fausses menaces

        return threats