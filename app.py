from flask import Flask, request, render_template
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

# Load model
with open("pickle/model.pkl", "rb") as file:
    gbc = pickle.load(file)

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        try:
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, -1)
            y_pred = gbc.predict(x)[0]
            y_proba = gbc.predict_proba(x)[0]

            if y_pred == 1:
                result_text = f"URL is safe with probability {y_proba[1]*100:.2f}%"
            else:
                result_text = f"URL is phishing with probability {y_proba[0]*100:.2f}%"
            
        except Exception as e:
            result_text = f"Error processing URL: {e}"

        return render_template('index.html', result=result_text, url=url)

    return render_template("index.html", result=None)
