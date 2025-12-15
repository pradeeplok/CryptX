function showTab(tabName) {
    // Hide all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => content.classList.remove('active'));

    // Remove active class from all tabs
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => tab.classList.remove('active'));

    // Show selected tab content
    document.getElementById(tabName + '-tab').classList.add('active');

    // Add active class to clicked tab
    event.target.classList.add('active');
}

function handleFileUpload() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    const filePreview = document.getElementById('filePreview');
    const fileContent = document.getElementById('fileContent');

    if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            fileContent.value = e.target.result;
            filePreview.style.display = 'block';
        };
        reader.readAsText(file);
    }
}

function analyzeFile() {
    const fileContent = document.getElementById('fileContent').value;
    if (fileContent.trim()) {
        analyzeCodeContent(fileContent);
    }
}

function analyzeCode() {
    const code = document.getElementById('codeInput').value;
    if (code.trim()) {
        analyzeCodeContent(code);
    } else {
        alert('Please enter some code to analyze');
    }
}

function clearCode() {
    document.getElementById('codeInput').value = '';
    document.getElementById('result').style.display = 'none';
}

function clearHex() {
    document.getElementById('hexInput').value = '';
    document.getElementById('cipherResult').style.display = 'none';
}

function identifyCipher() {
    const hexData = document.getElementById('hexInput').value;
    if (!hexData.trim()) {
        alert('Please enter hexadecimal data');
        return;
    }

    const resultDiv = document.getElementById('cipherResult');
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = '<div style="text-align: center; padding: 20px;"><h3>Analyzing ciphertext...</h3></div>';

    fetch('/identify_cipher', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ hex_data: hexData })
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                resultDiv.innerHTML = `<p class="error">Error: ${data.error}</p>`;
            } else {
                let html = '<h3>Identification Results:</h3>';

                // Top candidates
                html += '<div class="container glass-panel" style="margin-bottom: 20px;">';
                html += '<h4>Top Candidates:</h4>';
                data.top_candidates.forEach((candidate, idx) => {
                    const confidencePercent = (candidate.confidence * 100).toFixed(1);
                    const confidenceClass = candidate.confidence > 0.8 ? 'severity-high' :
                        candidate.confidence > 0.6 ? 'severity-medium' : 'severity-low';
                    html += `<div class="container ${confidenceClass}" style="margin: 10px 0;">`;
                    html += `<h5>#${idx + 1} - ${candidate.algorithm}</h5>`;
                    html += `<p><strong>Confidence:</strong> ${confidencePercent}%</p>`;
                    html += `<p><em>${candidate.reason}</em></p>`;
                    html += '</div>';
                });
                html += '</div>';

                // Advanced Analysis details (SIH-1681 Compliant)
                html += '<div class="container glass-panel">';
                html += '<h4>Advanced Statistical Fingerprints:</h4>';

                // Grid layout for stats
                html += '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 15px;">';
                html += `<div><strong>Data Length:</strong> ${data.analysis.data_length} bytes</div>`;
                html += `<div><strong>Entropy:</strong> ${data.analysis.entropy} / 8.0</div>`;
                html += `<div><strong>Compression Ratio:</strong> ${data.analysis.compression_ratio} (Target ~1.0)</div>`;
                html += `<div><strong>Bigram Repetition:</strong> ${data.analysis.bigram_repetition}</div>`;
                html += '</div>';

                html += '<table style="width:100%; border-collapse: collapse; margin-top: 10px;">';
                html += '<tr style="border-bottom: 1px solid #444;"><th>Feature</th><th>Value</th><th>Cryptographic Significance</th></tr>';
                html += `<tr><td>Skewness</td><td>${data.analysis.advanced.skewness}</td><td>Deviation from normal distribution</td></tr>`;
                html += `<tr><td>Kurtosis</td><td>${data.analysis.advanced.kurtosis}</td><td>Tail heaviness of byte curve</td></tr>`;
                html += `<tr><td>Chi-Square P-Value</td><td>${data.analysis.advanced.chi2_p_value}</td><td>Probability of uniformity (>0.05 is good)</td></tr>`;
                html += `<tr><td>Autocorrelation</td><td>${data.analysis.advanced.autocorrelation}</td><td>Pattern repetition (should be near 0)</td></tr>`;
                html += '</table>';

                if (data.analysis.block_analysis && data.analysis.block_analysis.length > 0) {
                    html += '<div style="margin-top: 15px;"><strong>Block Structure Analysis:</strong></div><ul>';
                    data.analysis.block_analysis.forEach(block => {
                        html += `<li>${block.block_size}-byte blocks: ${block.note} (Rep: ${(block.repetition_ratio * 100).toFixed(1)}%)</li>`;
                    });
                    html += '</ul>';
                }
                html += '</div>';

                resultDiv.innerHTML = html;

                // --- Explainability Section (Phase 3) ---
                // Create container if not exists
                if (!document.getElementById('explain-container')) {
                    const explainDiv = document.createElement('div');
                    explainDiv.id = 'explain-container';
                    explainDiv.className = 'container glass-panel';
                    explainDiv.style.marginTop = '20px';
                    explainDiv.innerHTML = `
                        <h4>Why this prediction? (AI Explanation)</h4>
                        <div id="explanation-loading">Loading explanation...</div>
                        <div id="explanation-content" style="display:none;">
                            <p>The <strong>Random Forest Model</strong> used the following features to make this decision:</p>
                            <div id="shap-chart" style="margin-top: 15px;"></div>
                        </div>
                    `;
                    resultDiv.appendChild(explainDiv);
                }

                // Call Explain Endpoint
                fetch('/explain_decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ciphertext: hexData })
                })
                    .then(res => res.json())
                    .then(expData => {
                        const loadingDiv = document.getElementById('explanation-loading');
                        const contentDiv = document.getElementById('explanation-content');

                        if (expData.error) {
                            loadingDiv.innerHTML = `<span style="color:red">Explanation failed: ${expData.error}</span>`;
                            return;
                        }

                        loadingDiv.style.display = 'none';
                        contentDiv.style.display = 'block';

                        // Render simplistic bar chart using HTML/CSS
                        let chartHtml = '<table class="table table-sm" style="color:white; width:100%;">';
                        chartHtml += '<thead><tr><th>Feature</th><th>Impact</th><th>Value</th></tr></thead><tbody>';

                        if (expData.top_features) {
                            expData.top_features.forEach(feat => {
                                // Impact ranges roughly -1 to 1 for logits, normalize for visual
                                let color = feat.impact > 0 ? '#4caf50' : '#f44336'; // Green vs Red
                                let width = Math.min(Math.abs(feat.impact) * 500, 100); // Scale factor

                                chartHtml += `<tr>
                                <td width="30%">${feat.feature}</td>
                                <td width="50%">
                                    <div style="display:flex; align-items:center;">
                                        <div style="background:${color}; width:${width}%; height:10px; border-radius:5px; margin-right:8px;"></div>
                                        <small>${feat.impact > 0 ? '+' : ''}${feat.impact.toFixed(4)}</small>
                                    </div>
                                </td>
                                <td width="20%">${feat.value.toFixed(4)}</td>
                            </tr>`;
                            });
                        }
                        chartHtml += '</tbody></table>';
                        document.getElementById('shap-chart').innerHTML = chartHtml;
                    })
                    .catch(err => {
                        console.error("Explain error:", err);
                        document.getElementById('explanation-loading').innerText = 'Error loading explanation.';
                    });
            }
        })
        .catch(error => {
            resultDiv.innerHTML = `<p class="error">Error: ${error.message}</p>`;
        });
}


function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function () {
        // Show feedback
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.background = '#28a745';
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '#28a745';
        }, 2000);
    });
}

function analyzeCodeContent(code) {
    const resultDiv = document.getElementById('result');

    resultDiv.style.display = 'block';
    resultDiv.innerHTML = '<div style="text-align: center; padding: 40px;"><h3>Analyzing your code...</h3><p>Please wait while we examine your cryptographic implementation...</p></div>';

    fetch('/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code: code })
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                resultDiv.innerHTML = `<p class="error">Error: ${data.error}</p>`;
            } else {
                html += `<p><strong>Detection:</strong> ${data.detection}</p>`;

                if (data.issues && data.issues.length > 0) {
                    html += '<h4>Security Issues Found:</h4>';
                    data.issues.forEach(issue => {
                        const severityClass = `severity-${issue.severity.toLowerCase()}`;
                        html += `<div class="container ${severityClass}">`;
                        html += `<h5>${issue.type} - ${issue.severity} Severity</h5>`;
                        html += `<p><strong>Problem:</strong> ${issue.problem}</p>`;
                        html += `<p><em>${issue.explanation}</em></p>`;
                        if (issue.cve_reference) {
                            html += `<p><small><strong>Reference:</strong> ${issue.cve_reference}</small></p>`;
                        }
                        html += '</div>';
                    });
                } else {
                    html += '<div class="container" style="border-left: 4px solid #28a745;"><p class="success">No security issues detected! Your code follows cryptographic best practices.</p></div>';
                }

                if (data.suggestions) {
                    html += `<h4>AI-Powered Suggestions:</h4><div class="container"><p>${data.suggestions}</p></div>`;
                }

                if (data.secure_snippets && Object.keys(data.secure_snippets).length > 0) {
                    html += '<h4>Educational: Secure Code Examples</h4>';
                    Object.values(data.secure_snippets).forEach(snippet => {
                        html += `<div class="container">`;
                        html += `<h5>${snippet.title}</h5>`;
                        html += `<p>${snippet.description}</p>`;
                        html += `<div class="code-snippet">`;
                        html += `<button class="copy-btn" onclick="copyToClipboard(\`${snippet.code.replace(/`/g, '\\`')}\`)">Copy Code</button>`;
                        html += snippet.code;
                        html += '</div>';
                        if (snippet.security_features) {
                            html += '<div class="security-features">';
                            html += '<strong>Security Features:</strong><ul>';
                            snippet.security_features.forEach(feature => {
                                html += `<li>${feature}</li>`;
                            });
                            html += '</ul></div>';
                        }
                        html += '</div>';
                    });
                }

                resultDiv.innerHTML = html;
            }
        })
        .catch(error => {
            resultDiv.innerHTML = `<p class="error">Error: ${error.message}</p>`;
        });
}

function loadHistory() {
    const historyList = document.getElementById('history-list');
    historyList.innerHTML = '<p>Loading history...</p>';

    fetch('/history')
        .then(response => response.json())
        .then(data => {
            if (data.length === 0) {
                historyList.innerHTML = '<p>No analysis history found.</p>';
                return;
            }

            let html = '';
            data.forEach(item => {
                html += `<div class="container glass-panel" style="border-left: 4px solid var(--primary-color); margin-bottom: 20px;">`;
                html += `<h5>${item.timestamp}</h5>`;
                html += `<p><strong>Detection:</strong> ${item.detection}</p>`;
                html += `<p><strong>Issues Found:</strong> ${item.issues_count}</p>`;
                html += `<div class="code-snippet" style="max-height: 100px; overflow: hidden; font-size: 12px; margin: 10px 0;">${item.code_snippet.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>`;
                html += `<button class="secondary" onclick="exportReport(${item.id})" style="font-size: 12px; margin-right: 5px;">JSON</button>`;
                html += `<button onclick="exportPdf(${item.id})" style="font-size: 12px; background: #ef4444; color: white;">PDF</button>`;
                html += `</div>`;
            });
            historyList.innerHTML = html;
        })
        .catch(error => {
            historyList.innerHTML = `<p class="error">Error loading history: ${error.message}</p>`;
        });
}

function exportReport(id) {
    window.location.href = `/export/${id}`;
}

function exportPdf(id) {
    window.location.href = `/export_pdf/${id}`;
}

function runCbcDemo() {
    fetch('/demo/cbc_image')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
                return;
            }
            document.getElementById('cbc-demo-result').style.display = 'block';
            document.getElementById('cbc-image').src = 'data:image/png;base64,' + data.image_data;
            document.getElementById('cbc-explanation').innerText = data.explanation;
        })
        .catch(error => alert('Error running demo: ' + error.message));
}

function runBitFlipDemo() {
    fetch('/demo/bitflip')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
                return;
            }
            document.getElementById('bitflip-demo-result').style.display = 'block';
            document.getElementById('bf-original').innerText = data.original;
            document.getElementById('bf-ciphertext').innerText = data.modified_ciphertext_hex;
            document.getElementById('bf-decrypted').innerText = data.decrypted;
            document.getElementById('bf-explanation').innerText = data.explanation;
        })
        .catch(error => alert('Error running demo: ' + error.message));
}
