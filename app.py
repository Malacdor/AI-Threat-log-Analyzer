# AI Threat Log Analyzer with Network Traffic Support
# A Flask-based web application for analyzing system logs and network traffic using ML and AI

import os
import re
import json
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from werkzeug.utils import secure_filename
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import requests

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'log', 'txt', 'json', 'pcap', 'pcapng', 'cap'}

# Create uploads directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==================== NETWORK TRAFFIC PARSER ====================

class NetworkTrafficParser:
    """Parse Wireshark text exports and PCAP files"""
    
    @staticmethod
    def is_wireshark_text(lines):
        """Detect if file is Wireshark text export"""
        sample = '\n'.join(lines[:5])
        return 'Frame' in sample and 'Protocol' in sample and 'No.' in sample
    
    @staticmethod
    def is_pcap_file(filepath):
        """Check if file is a PCAP binary file"""
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(4)
                # PCAP magic numbers
                return magic in [
                    b'\xa1\xb2\xc3\xd4',  # Standard PCAP
                    b'\xd4\xc3\xb2\xa1',  # PCAP (different endian)
                    b'\x0a\x0d\x0d\x0a',  # PCAPNG
                ]
        except:
            return False
    
    @staticmethod
    def parse_wireshark_text(lines):
        """Parse Wireshark text export format"""
        packets = []
        current_packet = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Match packet header: "No.     Time           Source ..."
            if line.startswith('No.') and 'Time' in line:
                continue
            
            # Match packet number line
            packet_match = re.match(r'^\s*(\d+)\s+([\d.]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(.+)$', line)
            if packet_match:
                if current_packet:
                    packets.append(current_packet)
                
                current_packet = {
                    'number': int(packet_match.group(1)),
                    'time': float(packet_match.group(2)),
                    'source': packet_match.group(3),
                    'destination': packet_match.group(4),
                    'protocol': packet_match.group(5),
                    'length': int(packet_match.group(6)),
                    'info': packet_match.group(7),
                    'raw': line,
                    'details': []
                }
            elif current_packet:
                # Add detail lines to current packet
                current_packet['details'].append(line)
        
        if current_packet:
            packets.append(current_packet)
        
        return packets
    
    @staticmethod
    def parse_pcap_with_scapy(filepath):
        """Parse PCAP file using scapy"""
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP
            
            packets_data = []
            pcap_packets = rdpcap(filepath)
            
            for i, pkt in enumerate(pcap_packets):
                packet_info = {
                    'number': i + 1,
                    'time': float(pkt.time),
                    'length': len(pkt),
                    'raw': str(pkt.summary()),
                    'details': []
                }
                
                # Extract IP layer info
                if IP in pkt:
                    packet_info['source'] = pkt[IP].src
                    packet_info['destination'] = pkt[IP].dst
                    packet_info['protocol'] = pkt[IP].proto
                else:
                    packet_info['source'] = 'N/A'
                    packet_info['destination'] = 'N/A'
                    packet_info['protocol'] = 'N/A'
                
                # Determine protocol name
                if TCP in pkt:
                    packet_info['protocol'] = 'TCP'
                    packet_info['sport'] = pkt[TCP].sport
                    packet_info['dport'] = pkt[TCP].dport
                    packet_info['info'] = f"TCP {pkt[TCP].sport} → {pkt[TCP].dport}"
                elif UDP in pkt:
                    packet_info['protocol'] = 'UDP'
                    packet_info['sport'] = pkt[UDP].sport
                    packet_info['dport'] = pkt[UDP].dport
                    packet_info['info'] = f"UDP {pkt[UDP].sport} → {pkt[UDP].dport}"
                elif ICMP in pkt:
                    packet_info['protocol'] = 'ICMP'
                    packet_info['info'] = f"ICMP type={pkt[ICMP].type}"
                else:
                    packet_info['info'] = packet_info['raw']
                
                packets_data.append(packet_info)
            
            return packets_data
        except ImportError:
            raise Exception("Scapy not installed. Install with: pip install scapy")
        except Exception as e:
            raise Exception(f"PCAP parsing failed: {str(e)}")

# ==================== LOG PARSER ====================

class LogParser:
    """Auto-detects and parses various log formats"""
    
    @staticmethod
    def detect_format(lines, filepath=None):
        """Detect log format from sample lines"""
        # Check if it's a PCAP file first
        if filepath and NetworkTrafficParser.is_pcap_file(filepath):
            return 'pcap'
        
        # Check if it's Wireshark text
        if NetworkTrafficParser.is_wireshark_text(lines):
            return 'wireshark_text'
        
        sample = '\n'.join(lines[:10])
        
        if re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', sample):
            return 'iso8601'
        elif re.search(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', sample):
            return 'syslog'
        elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', sample):
            return 'apache'
        elif '"timestamp"' in sample or '"time"' in sample:
            return 'json'
        else:
            return 'generic'
    
    @staticmethod
    def parse_syslog(line):
        """Parse syslog format: Oct 28 10:15:32 hostname service: message"""
        pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s+(.+)'
        match = re.search(pattern, line)
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'service': match.group(3),
                'message': match.group(4),
                'raw': line
            }
        return None
    
    @staticmethod
    def parse_iso8601(line):
        """Parse ISO8601 format: 2024-10-28T10:15:32Z level service: message"""
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\w\+\-:]*)\s+(\w+)\s+(\S+):\s+(.+)'
        match = re.search(pattern, line)
        if match:
            return {
                'timestamp': match.group(1),
                'level': match.group(2),
                'service': match.group(3),
                'message': match.group(4),
                'raw': line
            }
        return None
    
    @staticmethod
    def parse_apache(line):
        """Parse Apache/Nginx access logs"""
        pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[([^\]]+)\]\s+"(\w+)\s+([^"]+)"\s+(\d+)\s+(\d+)'
        match = re.search(pattern, line)
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'path': match.group(4),
                'status': match.group(5),
                'size': match.group(6),
                'raw': line
            }
        return None
    
    @staticmethod
    def parse_json(line):
        """Parse JSON log entries"""
        try:
            data = json.loads(line)
            data['raw'] = line
            return data
        except:
            return None
    
    @staticmethod
    def parse_generic(line):
        """Fallback parser for unknown formats"""
        return {
            'raw': line,
            'message': line.strip()
        }
    
    @classmethod
    def parse_logs(cls, file_path):
        """Main parsing function with auto-detection"""
        # Check if it's a PCAP file
        if NetworkTrafficParser.is_pcap_file(file_path):
            packets = NetworkTrafficParser.parse_pcap_with_scapy(file_path)
            return packets, 'pcap'
        
        # Otherwise read as text
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        if not lines:
            return [], 'empty'
        
        # Check for Wireshark text export
        if NetworkTrafficParser.is_wireshark_text(lines):
            packets = NetworkTrafficParser.parse_wireshark_text(lines)
            return packets, 'wireshark_text'
        
        log_format = cls.detect_format(lines, file_path)
        parsed_logs = []
        
        parser_map = {
            'syslog': cls.parse_syslog,
            'iso8601': cls.parse_iso8601,
            'apache': cls.parse_apache,
            'json': cls.parse_json,
            'generic': cls.parse_generic
        }
        
        parser = parser_map.get(log_format, cls.parse_generic)
        
        for line in lines:
            parsed = parser(line)
            if parsed:
                parsed_logs.append(parsed)
        
        return parsed_logs, log_format

# ==================== ANOMALY DETECTOR ====================

class AnomalyDetector:
    """Isolation Forest-based anomaly detection"""
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.encoders = {}
    
    def extract_features_network(self, packets):
        """Extract features from network packets"""
        features = []
        
        for pkt in packets:
            feature_vec = []
            
            # Packet length
            feature_vec.append(pkt.get('length', 0))
            
            # Protocol encoding (simple hash)
            protocol = str(pkt.get('protocol', 'unknown'))
            feature_vec.append(hash(protocol) % 1000)
            
            # Source port (if available)
            feature_vec.append(pkt.get('sport', 0))
            
            # Destination port (if available)
            feature_vec.append(pkt.get('dport', 0))
            
            # Info length
            info = pkt.get('info', '')
            feature_vec.append(len(info))
            
            # Time delta (difference from previous packet)
            time_val = pkt.get('time', 0)
            feature_vec.append(float(time_val))
            
            features.append(feature_vec)
        
        return np.array(features)
    
    def extract_features(self, logs):
        """Extract numerical features from log entries"""
        features = []
        
        for log in logs:
            feature_vec = []
            
            # Message length
            msg = log.get('message', log.get('info', log.get('raw', '')))
            feature_vec.append(len(str(msg)))
            
            # Count special characters
            feature_vec.append(sum(1 for c in str(msg) if not c.isalnum() and not c.isspace()))
            
            # Count digits
            feature_vec.append(sum(1 for c in str(msg) if c.isdigit()))
            
            # Error keywords
            error_keywords = ['error', 'fail', 'denied', 'unauthorized', 'invalid', 'exception']
            feature_vec.append(sum(1 for kw in error_keywords if kw in str(msg).lower()))
            
            # Suspicious keywords
            suspicious = ['root', 'admin', 'sudo', 'password', 'auth', 'exploit', 'attack']
            feature_vec.append(sum(1 for kw in suspicious if kw in str(msg).lower()))
            
            # HTTP status or packet length (if present)
            status = log.get('status', log.get('length', 200))
            try:
                feature_vec.append(int(status))
            except:
                feature_vec.append(200)
            
            features.append(feature_vec)
        
        return np.array(features)
    
    def detect(self, logs, is_network=False):
        """Detect anomalies in parsed logs or network packets"""
        if len(logs) < 10:
            return [False] * len(logs), []
        
        # Use appropriate feature extraction
        if is_network:
            X = self.extract_features_network(logs)
        else:
            X = self.extract_features(logs)
        
        predictions = self.model.fit_predict(X)
        scores = self.model.score_samples(X)
        
        # -1 = anomaly, 1 = normal
        is_anomaly = predictions == -1
        
        # Get anomalous entries with scores
        anomalies = []
        for i, (is_anom, score) in enumerate(zip(is_anomaly, scores)):
            if is_anom:
                anomalies.append({
                    'index': i,
                    'log': logs[i],
                    'score': float(score),
                    'severity': 'high' if score < -0.5 else 'medium'
                })
        
        return is_anomaly, anomalies

# ==================== AI SUMMARIZER ====================

class OllamaSummarizer:
    """Generate summaries using local Ollama LLM"""
    
    def __init__(self, model='llama3.2', base_url='http://localhost:11434'):
        self.model = model
        self.base_url = base_url
    
    def generate_summary(self, anomalies, log_format):
        """Generate natural language summary of findings"""
        if not anomalies:
            return "No significant anomalies detected. All log entries appear normal."
        
        # Prepare context for the LLM
        is_network = log_format in ['pcap', 'wireshark_text']
        
        if is_network:
            context = f"Analyzed {len(anomalies)} suspicious network packets from {log_format} capture.\n\n"
            context += "Sample anomalies:\n"
            
            for i, anom in enumerate(anomalies[:5]):
                pkt = anom['log']
                src = pkt.get('source', 'N/A')
                dst = pkt.get('destination', 'N/A')
                proto = pkt.get('protocol', 'N/A')
                info = pkt.get('info', '')[:100]
                context += f"{i+1}. [{anom['severity'].upper()}] {src} → {dst} ({proto}): {info}\n"
            
            prompt = f"""You are a network security analyst. Analyze these suspicious network packets and provide a brief summary.

{context}

Provide a concise summary covering:
1. What types of suspicious network activities were detected
2. Potential threats (port scans, DDoS, unusual protocols, etc.)
3. The severity level (high/medium/low)
4. Recommended actions

Keep it under 200 words and use clear, professional language."""
        else:
            context = f"Analyzed {len(anomalies)} suspicious log entries (Format: {log_format}).\n\n"
            context += "Sample anomalies:\n"
            
            for i, anom in enumerate(anomalies[:5]):
                log = anom['log']
                msg = log.get('message', log.get('raw', ''))[:200]
                context += f"{i+1}. [{anom['severity'].upper()}] {msg}\n"
            
            prompt = f"""You are a cybersecurity analyst. Analyze these log anomalies and provide a brief summary.

{context}

Provide a concise summary covering:
1. What types of suspicious activities were detected
2. The severity level (high/medium/low)
3. Recommended actions

Keep it under 200 words and use clear, professional language."""

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=60
            )
            
            if response.status_code == 200:
                return response.json()['response']
            else:
                return self._fallback_summary(anomalies, is_network)
        except Exception as e:
            print(f"Ollama error: {e}")
            return self._fallback_summary(anomalies, is_network)
    
    def _fallback_summary(self, anomalies, is_network=False):
        """Fallback template-based summary if Ollama fails"""
        high = sum(1 for a in anomalies if a['severity'] == 'high')
        medium = len(anomalies) - high
        
        if is_network:
            summary = f"Network traffic analysis detected {len(anomalies)} anomalies: "
            summary += f"{high} high-severity and {medium} medium-severity packets.\n\n"
            summary += "Anomalous patterns may include unusual protocols, port activity, "
            summary += "packet sizes, or connection patterns.\n\n"
            summary += "Recommendation: Investigate high-severity packets for potential "
            summary += "port scans, DDoS attempts, or unauthorized access."
        else:
            summary = f"Analysis detected {len(anomalies)} anomalies: "
            summary += f"{high} high-severity and {medium} medium-severity events.\n\n"
            summary += "Common patterns include unusual message lengths, suspicious keywords, "
            summary += "or atypical activity patterns.\n\n"
            summary += "Recommendation: Review flagged entries manually and investigate "
            summary += "high-severity items immediately."
        
        return summary

# ==================== FLASK ROUTES ====================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template_string(INDEX_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'logfile' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['logfile']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Use .log, .txt, .json, .pcap, or .pcapng'}), 400
    
    # Save uploaded file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        # Parse logs
        logs, log_format = LogParser.parse_logs(filepath)
        
        if not logs:
            return jsonify({'error': 'No valid log entries found'}), 400
        
        # Detect if it's network traffic
        is_network = log_format in ['pcap', 'wireshark_text']
        
        # Detect anomalies
        detector = AnomalyDetector(contamination=0.1)
        is_anomaly, anomalies = detector.detect(logs, is_network=is_network)
        
        # Generate AI summary
        summarizer = OllamaSummarizer()
        summary = summarizer.generate_summary(anomalies, log_format)
        
        # Prepare highlighted logs
        highlighted_logs = []
        for i, log in enumerate(logs[:500]):  # Limit to first 500 for display
            if is_network:
                raw_display = f"{log.get('number', i)} | {log.get('source', 'N/A')} → {log.get('destination', 'N/A')} | {log.get('protocol', 'N/A')} | {log.get('info', '')}"
            else:
                raw_display = log.get('raw', str(log))
            
            highlighted_logs.append({
                'raw': raw_display[:500],  # Truncate long lines
                'is_anomaly': bool(is_anomaly[i]),
                'index': i
            })
        
        # Clean up uploaded file
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'log_format': log_format,
            'total_entries': len(logs),
            'anomaly_count': len(anomalies),
            'anomalies': anomalies[:100],  # Limit to 100 anomalies for display
            'summary': summary,
            'highlighted_logs': highlighted_logs,
            'is_network': is_network
        })
    
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

# ==================== HTML TEMPLATE ====================

INDEX_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Threat Log Analyzer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .upload-section {
            text-align: center;
            padding: 40px 20px;
        }
        
        .file-input-wrapper {
            position: relative;
            display: inline-block;
            margin: 20px 0;
        }
        
        .file-input-wrapper input[type=file] {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }
        
        .file-input-label {
            display: inline-block;
            padding: 15px 30px;
            background: #667eea;
            color: white;
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.3s;
            font-size: 1.1em;
        }
        
        .file-input-label:hover {
            background: #5568d3;
        }
        
        .file-name {
            margin: 10px 0;
            color: #666;
        }
        
        .analyze-btn {
            padding: 15px 50px;
            background: #764ba2;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1.1em;
            cursor: pointer;
            transition: background 0.3s;
            margin-top: 10px;
        }
        
        .analyze-btn:hover:not(:disabled) {
            background: #643a8c;
        }
        
        .analyze-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .results {
            display: none;
        }
        
        .results.show {
            display: block;
        }
        
        .summary-box {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        
        .log-viewer {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            max-height: 500px;
            overflow-y: auto;
            margin: 20px 0;
        }
        
        .log-line {
            padding: 5px;
            margin: 2px 0;
            border-left: 3px solid transparent;
            word-wrap: break-word;
        }
        
        .log-line.anomaly {
            background: rgba(255, 59, 48, 0.1);
            border-left-color: #ff3b30;
        }
        
        .anomaly-list {
            margin: 20px 0;
        }
        
        .anomaly-item {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        
        .anomaly-item.high {
            background: #f8d7da;
            border-left-color: #dc3545;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .severity-high {
            background: #dc3545;
            color: white;
        }
        
        .severity-medium {
            background: #ffc107;
            color: #000;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            display: none;
        }
        
        .loading.show {
            display: block;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            display: none;
        }
        
        .error.show {
            display: block;
        }
        
        .network-badge {
            display: inline-block;
            background: #17a2b8;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AI Threat Log Analyzer</h1>
            <p>Upload system logs, network captures (PCAP), or Wireshark exports to detect anomalies</p>
        </div>
        
        <div class="card upload-section">
            <h2>Upload Log File or Network Capture</h2>
            <p style="color: #666; margin: 10px 0;">Supports: .log, .txt, .json, .pcap, .pcapng files</p>
            
            <div class="file-input-wrapper">
                <input type="file" id="logfile" accept=".log,.txt,.json,.pcap,.pcapng,.cap">
                <label class="file-input-label" for="logfile">Choose File</label>
            </div>
            
            <div class="file-name" id="fileName">No file selected</div>
            
            <button class="analyze-btn" id="analyzeBtn" disabled>Analyze</button>
        </div>
        
        <div class="error" id="errorBox"></div>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p style="margin-top: 20px; color: white; font-size: 1.1em;">Analyzing...</p>
        </div>
        
        <div class="results" id="results">
            <div class="card">
                <h2>Analysis Results <span id="networkBadge"></span></h2>
                
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-value" id="totalEntries">0</div>
                        <div class="stat-label">Total Entries</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="anomalyCount">0</div>
                        <div class="stat-label">Anomalies Detected</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="logFormat">-</div>
                        <div class="stat-label">Format</div>
                    </div>
                </div>
                
                <div class="summary-box">
                    <h3>AI Summary</h3>
                    <p id="aiSummary">-</p>
                </div>
                
                <h3>Detected Anomalies</h3>
                <div class="anomaly-list" id="anomalyList"></div>
                
                <h3>Viewer (Highlighted)</h3>
                <div class="log-viewer" id="logViewer"></div>
            </div>
        </div>
    </div>
    
    <script>
        const fileInput = document.getElementById('logfile');
        const fileName = document.getElementById('fileName');
        const analyzeBtn = document.getElementById('analyzeBtn');
        const loading = document.getElementById('loading');
        const results = document.getElementById('results');
        const errorBox = document.getElementById('errorBox');
        
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                fileName.textContent = this.files[0].name;
                analyzeBtn.disabled = false;
            } else {
                fileName.textContent = 'No file selected';
                analyzeBtn.disabled = true;
            }
        });
        
        analyzeBtn.addEventListener('click', async function() {
            const file = fileInput.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('logfile', file);
            
            // Show loading, hide results and errors
            loading.classList.add('show');
            results.classList.remove('show');
            errorBox.classList.remove('show');
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.error) {
                    throw new Error(data.error);
                }
                
                // Display results
                displayResults(data);
                
            } catch (error) {
                errorBox.textContent = 'Error: ' + error.message;
                errorBox.classList.add('show');
            } finally {
                loading.classList.remove('show');
            }
        });
        
        function displayResults(data) {
            // Update stats
            document.getElementById('totalEntries').textContent = data.total_entries;
            document.getElementById('anomalyCount').textContent = data.anomaly_count;
            document.getElementById('logFormat').textContent = data.log_format.toUpperCase();
            document.getElementById('aiSummary').textContent = data.summary;
            
            // Show network badge if it's network traffic
            const networkBadge = document.getElementById('networkBadge');
            if (data.is_network) {
                networkBadge.innerHTML = '<span class="network-badge">📡 Network Traffic</span>';
            } else {
                networkBadge.innerHTML = '';
            }
            
            // Display anomalies
            const anomalyList = document.getElementById('anomalyList');
            anomalyList.innerHTML = '';
            
            if (data.anomalies.length === 0) {
                anomalyList.innerHTML = '<p style="color: #28a745;">✅ No anomalies detected. All entries appear normal.</p>';
            } else {
                data.anomalies.forEach(anom => {
                    const div = document.createElement('div');
                    div.className = `anomaly-item ${anom.severity}`;
                    
                    const badge = document.createElement('span');
                    badge.className = `severity-badge severity-${anom.severity}`;
                    badge.textContent = anom.severity.toUpperCase();
                    
                    let display = '';
                    if (data.is_network) {
                        const pkt = anom.log;
                        display = `Packet #${pkt.number || anom.index}: ${pkt.source || 'N/A'} → ${pkt.destination || 'N/A'} (${pkt.protocol || 'N/A'})<br>`;
                        display += `<code>${(pkt.info || pkt.raw || '').substring(0, 300)}</code>`;
                    } else {
                        const msg = anom.log.message || anom.log.raw || '';
                        display = `<code>${msg.substring(0, 300)}</code>`;
                    }
                    
                    div.innerHTML = badge.outerHTML + '<br>' + display;
                    anomalyList.appendChild(div);
                });
            }
            
            // Display highlighted logs
            const logViewer = document.getElementById('logViewer');
            logViewer.innerHTML = '';
            
            data.highlighted_logs.forEach(log => {
                const div = document.createElement('div');
                div.className = `log-line ${log.is_anomaly ? 'anomaly' : ''}`;
                div.textContent = log.raw;
                logViewer.appendChild(div);
            });
            
            results.classList.add('show');
        }
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    print("=" * 60)
    print("AI Threat Log Analyzer - Network Edition")
    print("=" * 60)
    print("\n🚀 Starting Flask server...")
    print("📝 Make sure Ollama is running: ollama serve")
    print("📦 Supports: Logs, PCAP files, Wireshark exports")
    print("🌐 Open http://localhost:5000 in your browser\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
