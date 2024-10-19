import pickle
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# Load Data
def load_data():
    with open('../dataset/flowdata.pickle', 'rb') as file:
        x_train, y_train, x_test, y_test = pickle.load(file, encoding='bytes')
    return x_train, y_train, x_test, y_test

# Preprocessing Data
def preprocess_data(x_train, x_test):
    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)
    return x_train_scaled, x_test_scaled

# Train Model
def train_model(x_train, y_train, x_test, y_test):
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    lr_model = LogisticRegression(random_state=42)
    
    rf_model.fit(x_train, y_train)
    rf_predictions = rf_model.predict(x_test)
    print("Random Forest - Accuracy: ", accuracy_score(y_test, rf_predictions))
    print("Random Forest - Classification Report:\n", classification_report(y_test, rf_predictions))
    
    lr_model.fit(x_train, y_train)
    lr_predictions = lr_model.predict(x_test)
    print("Logistic Regression - Accuracy: ", accuracy_score(y_test, lr_predictions))
    print("Logistic Regression - Classification Report:\n", classification_report(y_test, lr_predictions))
    
    return rf_model, lr_model

# Save and Load Model
def save_model(model, filename):
    with open(filename, 'wb') as file:
        pickle.dump(model, file)

def load_model(filename):
    with open(filename, 'rb') as file:
        model = pickle.load(file)
    return model

# Main Execution
if __name__ == "__main__":
    x_train, y_train, x_test, y_test = load_data()
    x_train_scaled, x_test_scaled = preprocess_data(x_train, x_test)
    rf_model, lr_model = train_model(x_train_scaled, y_train, x_test_scaled, y_test)

    # Save the best performing model (example: Random Forest)
    save_model(rf_model, 'botnet_rf_model.pkl')
    save_model(lr_model, 'botnet_lr_model.pkl')
