from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Load the tokenizer and model
tokenizer = AutoTokenizer.from_pretrained("kmack/malicious-url-detection")
model = AutoModelForSequenceClassification.from_pretrained("kmack/malicious-url-detection")

def predict_url(url):
    """
    Predict if the given URL is malicious or benign.
    :param url: str, the URL to classify
    :return: str, 'Malicious' or 'Benign'
    """
    try:
        # Tokenize the input
        inputs = tokenizer(url, return_tensors="pt", truncation=True, padding=True)

        # Make a prediction
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            prediction = torch.argmax(logits, dim=1).item()

        # Map prediction to labels
        return "Malicious" if prediction == 1 else "Benign"
    except Exception as e:
        print(f"Error in prediction: {e}")
        return "Unknown"
