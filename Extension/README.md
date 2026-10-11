## Running the backend
1. cd Extension
2. uv sync
3. (PowerShell) $env:PYTHONDONTWRITEBYTECODE = "1"
4. uv run main.py
The first run downloads the Hugging Face model (~250 MB).