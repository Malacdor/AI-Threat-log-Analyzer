This is A Python-based web application that uses Machine Learning and AI to analyze system logs and network traffic captures for suspicious activity and security threats.

## How It Works
The AI Threat Log Analyzer combines traditional machine learning with modern AI to automatically detect and explain anomalies in log files and network traffic:

### 1 File Uploading and Auto-Detection
Upload any supported file through the web interface. The app automatically detects the file format:
- System logs (syslog, ISO8601 timestamps)
- Web server logs (Apache, Nginx)
- JSON-formatted application logs
- Network packet captures (PCAP, PCAPNG)
- Wireshark text exports

### 2. Log Parsing
The parser extracts structured information from your files:
- **For logs**: timestamps, hostnames, services, messages, error codes
- **For network traffic**: source/destination IPs, protocols, ports, packet sizes, timing

### 3. Machine Learning Anomaly Detection
Uses scikit-learn's Isolation Forest algorithm to identify unusual patterns:
- **For logs**: Analyzes message length, special character density, error keywords, suspicious terms
- **For network traffic**: Examines packet sizes, protocol distribution, port activity, timing patterns
- Flags the top 10% most anomalous entries (configurable)

### 4. AI-Powered Explanations
Detected anomalies are sent to Ollama (local LLM) which generates:
- Natural language summary of findings
- Threat severity assessment (high/medium/low)
- Specific security concerns (port scans, unauthorized access, etc.)
- Recommended actions for investigation

### 5. Visual Results
The web interface displays:
- Statistics dashboard (total entries, anomalies found, format detected)
- AI-generated security summary
- Detailed list of suspicious entries with severity badges
- Full log viewer with highlighted anomalous lines in red

---

## System Requirements

### Operating System
- **Windows** 10/11
- **macOS** unsure
- **Linux** (any modern distribution)

### Software Requirements

#### 1. Python
- **Version**: Python 3.8 or later
- **Download**: https://www.python.org/downloads/

#### 2. Ollama (Local AI Model)
- **Purpose**: Generates natural language summaries of security findings
- **Installation**: 
  - Download from: https://ollama.com/download
- **Required Model**: llama3.2 (or compatible LLM)

#### 3. Python Virtual Environment
- Built into Python 3.3+

### Hardware Requirements

#### Minimum (for olama):
- **CPU**: Dual-core processor (2 GHz+)
- **RAM**: 4GB
- **Storage**: 5GB free space (for Ollama and dependencies)
- **Network**: Internet connection for initial setup only

#### Recommended:
- **CPU**: Quad-core processor (3 GHz+)
- **RAM**: 8GB or more
- **Storage**: 10GB free space
- For analyzing large PCAP files (100MB+), more RAM improves performance

### Python Package Dependencies

These are installed automatically via `requirements.txt`:

1. **Flask** (3.0.0)
   - Web framework for the user interface
   
2. **pandas** (2.1.3)
   - Data manipulation and analysis
   
3. **numpy** (1.26.2)
   - Numerical computing for ML algorithms
   
4. **scikit-learn** (1.3.2)
   - Machine learning library (Isolation Forest)
   
5. **requests** (2.31.0)
   - HTTP library for Ollama API communication
   
6. **Werkzeug** (3.0.1)
   - WSGI utilities for Flask
   
7. **scapy** (2.5.0)
   - Network packet parsing for PCAP files

### Network Requirements

- **Port 5000**: Used by Flask web server (local only)
- **Port 11434**: Used by Ollama (local only)
- **Firewall**: No inbound connections required (all local)

---

## Installation & Setup

### Step 1: Install Python
1. Download Python from https://www.python.org/downloads/
2. During installation, **check "Add Python to PATH"**
3. Verify: `python --version`

### Step 2: Install Ollama
1. Download from https://ollama.com/download
2. Run the installer for your operating system
3. After installation, open terminal/command prompt
4. Download the AI model:
   ```bash
   ollama pull llama3.2
   ```
5. Verify installation:
   ```bash
   ollama list
   ```
   You should see `llama3.2` in the list

### Step 3: Set Up the Application
1. **Create project folder** and navigate to it:
   ```bash
   mkdir ai-threat-log-analyzer
   cd ai-threat-log-analyzer
   ```

2. **Create the required files**:
   - `app.py` (main application code)
   - `requirements.txt` (Python dependencies)
   - `.gitignore` (Git ignore rules)
   - `README.md` (this file)

3. **Create virtual environment**:
   
   **Windows:**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```
   
   **Mac/Linux:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
   
   You should see `(venv)` at the start of your command line

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   This takes 2-5 minutes depending on your internet speed

### Step 4: Run the Application
1. **Make sure you're in the project folder with venv activated**
   ```bash
   cd path/to/ai-threat-log-analyzer
   venv\Scripts\activate  # Windows
   # or
   source venv/bin/activate  # Mac/Linux
   ```

2. **Start the app**:
   ```bash
   python app.py
   ```

3. **Open your browser**:
   - Go to: http://localhost:5000

4. **Upload a file and click "Analyze"**

---

## Supported File Types

### Text-Based Logs
- `.log` - Generic log files
- `.txt` - Plain text logs
- `.json` - JSON-formatted logs

### Network Traffic
- `.pcap` - Standard packet capture files
- `.pcapng` - Next-generation packet capture format
- `.cap` - Alternative packet capture extension
- Wireshark text exports (any extension)

### Maximum File Size
- Default: 100MB
- Can be adjusted in `app.py` if needed

---

## Troubleshooting

### "Module not found" errors
**Solution**: Make sure virtual environment is activated:
```bash
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux
```

### Ollama connection errors
**Solution**: Ensure Ollama is running:
```bash
ollama list  # Should show llama3.2
```

### PCAP parsing errors
**Solution**: Install scapy properly:
```bash
pip install scapy
```

### Large files causing timeouts
**Solution**: Break large files into smaller chunks or increase timeout in `app.py`

### Port 5000 already in use
**Solution**: Change port in `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)
```

## Privacy & Security
- **All processing is local** - no data sent to external servers
- **Ollama runs on your machine** - AI analysis stays private
- **No internet required** (after initial setup)
- **Temporary files** are deleted after analysis
- **No logging** of uploaded file contents
