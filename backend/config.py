
import os
from pathlib import Path
from dotenv import load_dotenv

# Gets the folder where this config.py file is located
BASE_DIR = Path(__file__).resolve().parent

# Load API keys from .env file
load_dotenv(BASE_DIR / ".env")

# Retrieves the VT API key
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Retrieves IPQS API Key
IPQS_API_KEY = os.getenv("IPQS_API_KEY")

# Retrived URLScan.io API Key
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

# Retrives URLHaus API Key
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")

# Retrives MalwareBazaar API Key
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

# Retrieves the Gemini API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")