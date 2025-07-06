from flask import Flask, request, jsonify
import joblib
import numpy as np

app = Flask(__name__)

# Charger le modèle et le scaler
knn = joblib.load('models/knn_model.pkl')
scaler = joblib.load('models/scaler.pkl')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Récupérer les données du JSON
        data = request.get_json()
        nb_connexions = data['nb_connexions']
        duree_session = data['duree_session']

        # Préparer les données pour la prédiction
        input_data = np.array([[nb_connexions, duree_session]])
        input_data_scaled = scaler.transform(input_data)

        # Faire la prédiction
        prediction = knn.predict(input_data_scaled)[0]

        # Retourner la réponse
        return jsonify({'prediction': prediction})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(port=5000, debug=True)