from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allows your Chrome Extension to talk to your local backend server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze")
async def analyze_email(request: Request):
    # 1. Catch the raw JSON payload coming from background.js
    email_json = await request.json()
    
    # 2. Navigate to where Google stores headers inside the JSON
    headers = email_json.get('payload', {}).get('headers', [])
    
    # 3. Pull out the specific headers we want to read
    email_subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "No Subject")
    email_sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "Unknown Sender")
    email_date = next((h['value'] for h in headers if h['name'].lower() == 'date'), "No Date")
    
    # 4. Print them beautifully directly into your terminal/command line
    print("\n" + "="*50)
    print("📥 [NEW EMAIL RECEIVED FROM EXTENSION]")
    print(f"🆔 MESSAGE ID: {email_json.get('id')}")
    print(f"👤 SENDER:  {email_sender}")
    print(f"📧 SUBJECT: {email_subject}")
    print(f"📅 DATE:    {email_date}")
    print("="*50 + "\n")
    
    # 5. Send a quick success message back to the Chrome Extension
    return {
        "status": "Success",
        "message": f"Successfully read header for email: {email_subject}"
    }

if __name__ == "__main__":
    import uvicorn
    # Starts your local server on http://127.0.0.1:8000
    uvicorn.run(app, host="127.0.0.1", port=8000)