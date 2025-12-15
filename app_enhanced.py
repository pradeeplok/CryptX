from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import os
import io
from dotenv import load_dotenv
from xhtml2pdf import pisa
import database
from analyzer import detect_encryption, analyze_crypto_code, suggest_with_openai, generate_secure_code_snippets, create_cbc_demo, create_bitflip_demo
from cipher_classifier import classifier

# Load env variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Limit request size to 1MB to prevent DoS
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB

# Initialize Database
database.init_db()

# ---------------- SECURITY HEADERS ----------------
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ---------------- FLASK ROUTE ----------------
@app.route("/", methods=["GET"])
def home():
    return render_template('index.html')

@app.route("/history", methods=["GET"])
def history():
    try:
        history_data = database.get_history()
        return jsonify(history_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/export/<int:id>", methods=["GET"])
def export_report(id):
    try:
        analysis = database.get_analysis(id)
        if not analysis:
            return jsonify({"error": "Analysis not found"}), 404
        
        response = jsonify(analysis)
        response.headers["Content-Disposition"] = f"attachment; filename=analysis_report_{id}.json"
        return response
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/export_pdf/<int:id>", methods=["GET"])
def export_pdf(id):
    try:
        analyses = database.get_history()
        # Find the specific analysis by ID (inefficient but works for small history)
        analysis = next((item for item in analyses if item['id'] == id), None)
        
        if not analysis:
            return jsonify({"error": "Analysis not found"}), 404

        # Render HTML template
        html = render_template('report_pdf.html', **analysis)
        
        # Create PDF
        pdf_stream = io.BytesIO()
        pisa_status = pisa.CreatePDF(io.BytesIO(html.encode('utf-8')), dest=pdf_stream)
        
        if pisa_status.err:
             return jsonify({"error": f"PDF generation error: {pisa_status.err}"}), 500
             
        pdf_stream.seek(0)
        
        return send_file(
            pdf_stream,
            as_attachment=True,
            download_name=f"cryptx_report_{id}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({"error": f"Export failed: {str(e)}"}), 500

@app.route("/demo/cbc_image", methods=["GET"])
def demo_cbc_image():
    try:
        demo_data = create_cbc_demo()
        return jsonify(demo_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/demo/bitflip", methods=["GET"])
def demo_bitflip():
    try:
        demo_data = create_bitflip_demo()
        return jsonify(demo_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/identify_cipher", methods=["POST"])
def identify_cipher():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        hex_string = data.get("hex_data", "")
        if not hex_string:
            return jsonify({"error": "No hex data provided"}), 400
        
        # Input Validation
        if len(hex_string) > 500000:  # ~250KB
            return jsonify({"error": "Hex string too long"}), 400
        
        result = classifier.identify_algorithm(hex_string)
        
        if 'error' in result:
            return jsonify({"error": result['error']}), 400
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route('/explain_decision', methods=['POST'])
def explain_decision():
    """
    Explain the last classification decision using SHAP.
    Expects JSON: { "ciphertext": "hex_string..." }
    """
    try:
        if not request.json or 'ciphertext' not in request.json:
            return jsonify({'error': 'No ciphertext provided'}), 400
        
        hex_data = request.json['ciphertext']
        # Clean data
        hex_data = hex_data.replace(' ', '').replace('\n', '').strip()
        
        # Explain
        data_bytes = classifier.hex_to_bytes(hex_data)
        explanation = classifier.explain_prediction(data_bytes)
        
        return jsonify(explanation)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        code = data.get("code", "")
        if not code:
            return jsonify({"error": "No code provided"}), 400
            
        # Input Validation: Check code length
        if len(code) > 50000:
            return jsonify({"error": "Code too long. Please limit to 50,000 characters."}), 400
            
        # Input Validation: Ensure code is a string
        if not isinstance(code, str):
             return jsonify({"error": "Invalid input format. Code must be a string."}), 400

        detection = detect_encryption(code)
        issues = analyze_crypto_code(code)
        suggestions = suggest_with_openai(issues, code)
        
        # Save to database
        database.save_analysis(code, detection, len(issues))
        
        # Generate secure code snippets for educational purposes
        secure_snippets = generate_secure_code_snippets(issues, code)

        return jsonify({
            "detection": detection,
            "issues": issues,
            "suggestions": suggestions,
            "secure_snippets": secure_snippets
        })
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# ---------------- RUN ----------------
if __name__ == "__main__":
    from waitress import serve
    print("Starting production server on http://localhost:8080")
    serve(app, host='0.0.0.0', port=8080)
