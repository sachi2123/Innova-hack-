import os
from dotenv import load_dotenv

load_dotenv()

# Model configured across main app.py routes
model_name = 'gemini-3.1-flash-lite'

from google.genai import Client

try:
    client = Client()
    print(f"--- Testing {model_name} ---")
    response = client.models.generate_content(
        model=model_name,
        contents='Hello, say hi!'
    )
    print(f"SUCCESS: {model_name} response: {response.text}")
except Exception as e:
    print(f"FAILED: {model_name} error: {e}")

