from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np

app = Flask(__name__)

# Charger les modèles et les scalers
try:
    knn_model = joblib.load('models/knn_model.pkl')
    knn_scaler = joblib.load('models/scaler.pkl')
    failed_logins_model = joblib.load('models/failed_logins_model.pkl')
    failed_logins_scaler = joblib.load('models/scaler_failed_logins.pkl')
    print("Modèles et scalers chargés avec succès")
except Exception as e:
    print(f"Erreur lors du chargement des modèles ou scalers : {str(e)}")

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Récupérer les données du JSON
        data = request.get_json()
        nb_connexions = data['nb_connexions']
        duree_session = data['duree_session']

        # Log pour débogage
        print(f"Données reçues pour /predict : nb_connexions={nb_connexions}, duree_session={duree_session}")

        # Préparer les données pour la prédiction
        input_data = np.array([[nb_connexions, duree_session]])
        input_data_scaled = knn_scaler.transform(input_data)

        # Faire la prédiction
        prediction = knn_model.predict(input_data_scaled)[0]

        # Log pour débogage
        print(f"Prédiction pour /predict : {prediction}")

        # Retourner la réponse
        return jsonify({'prediction': prediction})
    except Exception as e:
        print(f"Erreur dans /predict : {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/predict-failed-logins', methods=['POST'])
def predict_failed_logins():
    try:
        # Récupérer les données de la requête
        data = request.get_json()
        failedLoginAttempts = data['failedLoginAttempts']
        time_since_last_failed = data['time_since_last_failed']
        nb_connexions = data['nb_connexions']

        # Log pour débogage
        print(f"Données reçues pour /predict-failed-logins : failedLoginAttempts={failedLoginAttempts}, time_since_last_failed={time_since_last_failed}, nb_connexions={nb_connexions}")

        # Préparer les données pour la prédiction
        input_data = pd.DataFrame({
            'failedLoginAttempts': [failedLoginAttempts],
            'time_since_last_failed': [time_since_last_failed],
            'nb_connexions': [nb_connexions]
        })

        # Normaliser les données
        input_data_scaled = failed_logins_scaler.transform(input_data)

        # Faire la prédiction
        prediction = failed_logins_model.predict(input_data_scaled)[0]

        # Log pour débogage
        print(f"Prédiction pour /predict-failed-logins : {prediction}")

        return jsonify({'prediction': prediction})
    except Exception as e:
        print(f"Erreur dans /predict-failed-logins : {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)