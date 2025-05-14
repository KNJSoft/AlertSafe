from sklearn.ensemble import IsolationForest
import numpy as np
import logging

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
            self.anomaly_detector.fit(normal_traffic_data)
            self.is_trained = True
            self.logger.info("Modèle de détection d'anomalies entraîné avec succès.")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'entraînement du modèle : {e}", exc_info=True)
            # Gérer l'erreur (par exemple, lever une exception, arrêter le programme, utiliser un modèle par défaut)
            raise  # Propager l'exception pour que l'appelant puisse la gérer

    def detect_threats(self, features):
        threats = []

        # Détection basée sur les signatures (triées par priorité)
        sorted_rules = sorted(self.signature_rules.items(), key=lambda item: item[1]['priority'])
        for rule_name, rule_data in sorted_rules:
            if rule_data['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'description': rule_data['description'],
                    'confidence': rule_data['confidence'],
                    'details': features  # Ajoute les features pour plus de contexte
                })

        # Détection d'anomalies
        if self.is_trained:
            feature_vector = np.array([[
                features['packet_size'],
                features['packet_rate'],
                features['byte_rate']
            ]])
            try:
                anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
                if anomaly_score < -0.5:  # Seuil d'anomalie
                    confidence = min(1.0, abs(anomaly_score))
                    threats.append({
                        'type': 'anomaly',
                        'score': anomaly_score,
                        'confidence': confidence,
                        'details': features
                    })
            except Exception as e:
                self.logger.error(f"Erreur lors de la détection d'anomalies : {e}", exc_info=True)
                # Gérer l'erreur (par exemple, ignorer l'échantillon, retourner une menace d'erreur)
                threats.append({
                    'type': 'error',
                    'message': 'Erreur lors de la détection d\'anomalie',
                    'details': str(e),
                    'confidence': 0.0
                })
        else:
            self.logger.warning("Le modèle d'anomalie n'est pas entraîné. La détection d'anomalies est désactivée.")

        return threats