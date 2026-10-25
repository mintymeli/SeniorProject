
import os
from pathlib import Path
from dotenv import load_dotenv

# Gets the folder where this config.py file is located
BASE_DIR = Path(__file__).resolve().parent

# Load API keys from .env file
load_dotenv(BASE_DIR / ".env")

# Retrieves the VT API key
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
