# CryptX - Smart Algorithm Recognition & Analysis

A Flask application that analyzes Python cryptographic code for security issues, provides AI-powered suggestions, and offers interactive educational demonstrations.

## Key Features

### Analysis & Explainability
- **Automated Detection**: Identifies encryption libraries (Cryptography, PyCryptodome, etc.) and algorithms.
- **Vulnerability Scanning**: Detects weak keys, ECB mode, hardcoded secrets, and more.
- **AI Suggestions**: Uses OpenAI to suggest fixes and best practices.
- **Secure Code Generation**: Generates secure, copy-paste ready code snippets.

### History & Reports
- **Persistence**: Saves analysis history to a local SQLite database.
- **History Tab**: View past analyses, including detection results and issue counts.
- **Export Reports**: Download analysis reports as JSON files.

### Interactive Demos
- **ECB Pattern Leakage**: Visual proof of why ECB mode is insecure for images.
- **CBC vs ECB**: Side-by-side comparison showing CBC's security.
- **CBC Bit Flipping**: Interactive demo of ciphertext mutability attacks.

## Setup & Run

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set your OpenAI API key:**
   ```bash
   # Windows PowerShell
   $env:OPENAI_API_KEY="your_actual_api_key_here"
   
   # Linux/Mac
   export OPENAI_API_KEY="your_actual_api_key_here"
   ```

3. **Run the application:**
   ```bash
   python app_enhanced.py
   ```
   The server will start on `http://localhost:8080`.

## Project Structure

- **`app_enhanced.py`**: Main Flask application entry point.
- **`analyzer.py`**: Core logic for code analysis and demo generation.
- **`database.py`**: SQLite database interactions.
- **`templates/`**: HTML templates.
- **`static/`**: CSS and JavaScript files.
- **`requirements.txt`**: Python dependencies.

## Security Features
- **Production Server**: Uses `waitress` instead of Flask's dev server.
- **Input Validation**: Limits request size (1MB) and code length (50k chars).
- **Secure Configuration**: API keys loaded from environment variables.
