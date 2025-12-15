from app_enhanced import app

app.config['TESTING'] = True
client = app.test_client()

print("--- Testing Home Route ---")
try:
    rv = client.get('/')
    print(f"Status Code: {rv.status_code}")
    print(f"Headers: {rv.headers}")
    if b'CryptX' in rv.data:
        print("Found 'CryptX' in body")
    else:
        print("'CryptX' NOT found in body")
        print(f"Body snippet: {rv.data[:200]}")
        
    if rv.headers.get('X-Frame-Options') == 'SAMEORIGIN':
        print("Security Headers Present")
    else:
        print("Security Headers MISSING")

except Exception as e:
    print(f"Error: {e}")
