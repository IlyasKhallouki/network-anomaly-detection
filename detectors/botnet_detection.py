import pickle
import scapy.all as scapy
import numpy as np
from sklearn.preprocessing import StandardScaler

class BotnetDetection:
    def __init__(self, model_path):
        """
        Initializes the BotnetDetection class and loads the pre-trained models.

        Args:
            model_path (str): The directory where the models are saved.
        """
        self.model_path = model_path
        self.models = {}
        self.scaler = None

        # Load the models
        self.load_models()

    def load_models(self):
        """
        Load the saved models from the given path.
        Assumes that the models are saved in `.pkl` format.
        """
        try:
            # Load Logistic Regression model
            with open(f'{self.model_path}/botnet_lr_model.pkl', 'rb') as model_file:
                self.models['lr'] = pickle.load(model_file)

            # Load Random Forest model
            with open(f'{self.model_path}/botnet_rf_model.pkl', 'rb') as model_file:
                self.models['rf'] = pickle.load(model_file)

            print("Models loaded successfully.")
        except Exception as e:
            print(f"Error loading models: {e}")

    def preprocess_data(self, data):
        """
        Preprocess the incoming data using the scaler to normalize it.

        Args:
            data (numpy.ndarray): The raw network data for prediction.

        Returns:
            numpy.ndarray: The preprocessed data.
        """
        # Apply scaling if a scaler exists, else return data as is
        if self.scaler:
            return self.scaler.transform(data)
        return data

    def predict(self, data):
        """
        Predict whether the given data is botnet traffic using the loaded models.

        Args:
            data (numpy.ndarray): The raw network data for prediction.

        Returns:
            dict: Predictions from each model.
        """
        # Preprocess the data (scaling)
        processed_data = self.preprocess_data(data)

        # Get predictions from each model
        predictions = {}
        for model_name, model in self.models.items():
            predictions[model_name] = model.predict(processed_data)
        
        return predictions

    def detect_anomalies(self, data):
        """
        Detect anomalies in the network traffic data. If both models predict botnet traffic, we consider it an anomaly.

        Args:
            data (numpy.ndarray): The raw network data for anomaly detection.

        Returns:
            bool: True if the data is identified as botnet traffic, False otherwise.
        """
        predictions = self.predict(data)
        
        # If both models classify the traffic as botnet (assuming 1 = Botnet)
        if all([pred == 1 for model_pred in predictions.values() for pred in model_pred]):
            print("Anomaly detected: Botnet traffic.")
            return True
        else:
            print("No anomaly detected: Normal traffic.")
            return False

    def sniff_and_extract_features(self, packet):
        """
        Extract features from a sniffed packet that the model can use for detection.

        Args:
            packet (scapy.Packet): The packet object from the packet sniffer.

        Returns:
            list: The features extracted from the packet.
        """
        # Example features: You can adjust this depending on what the model expects
        features = []
        
        # Extract packet-related features (modify this based on the model's expected input)
        features.append(len(packet))  # Packet length
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src  # Source IP
            ip_dst = packet[scapy.IP].dst  # Destination IP
            features.extend([ip_src, ip_dst])  # Add IP addresses to features
        
        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            features.append(packet.sport)  # Source port
            features.append(packet.dport)  # Destination port
        
        return features

    def live_packet_analysis(self, interface="eth0", timeout=60):
        """
        Sniff live packets from the network interface and run botnet detection.

        Args:
            interface (str): The network interface to sniff on (default is eth0).
            timeout (int): The time duration to sniff packets (in seconds).
        """
        print(f"Sniffing on interface: {interface} for {timeout} seconds...")
        packets = scapy.sniff(iface=interface, timeout=timeout, prn=self.packet_callback)

    def packet_callback(self, packet):
        """
        Callback function to be called for each sniffed packet.

        Args:
            packet (scapy.Packet): The sniffed packet.
        """
        features = self.sniff_and_extract_features(packet)
        features_np = np.array(features).reshape(1, -1)  # Reshape as needed for prediction

        # Detect botnet traffic based on the features extracted
        is_botnet = self.detect_anomalies(features_np)
        if is_botnet:
            print("Botnet traffic detected in packet!")
