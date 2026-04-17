#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, jsonify, Response, session, flash
import os
import time
import json
import threading
import glob
import datetime
from werkzeug.utils import secure_filename
from suricata_parser import SuricataLogParser
import pickle
import numpy as np
from collections import defaultdict
from functools import wraps

app = Flask(__name__)

# Configuration
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'uploads')
HOSTS_DIR = os.path.join(APP_ROOT, 'hosts') # Directory for host-specific files
ALLOWED_EXTENSIONS = {"json"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SECRET_KEY"] = "suricata_classifier_secret_key"

# Default login credentials
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "password"

# Global variables for processing status and results (Consider using a more robust storage like Redis for production)
processing_status = {}
processed_results = {}

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(HOSTS_DIR, exist_ok=True) # Ensure hosts directory exists

class WebSuricataClassifier:
    def __init__(self, model_dir="models"):
        """Initialize classifier with models from specified directory"""
        self.model_dir = os.path.join(APP_ROOT, model_dir)
        # Check if suricata_parser exists and handle potential import error
        try:
            self.parser = SuricataLogParser(model_dir=self.model_dir)
        except NameError:
            print("ERROR: SuricataLogParser class not found. Make sure suricata_parser.py is present and correct.")
            self.parser = None
        except Exception as e:
            print(f"Error initializing SuricataLogParser: {e}")
            self.parser = None
            
        self.model_binary = self._load_model("XGBoost_binary_retrained.pkl")
        self.model_multi = self._load_model("XGBoost_multi_retrained.pkl")
        encoder_path = os.path.join(self.model_dir, "label_encoder_multi_retrained.pkl")
        self.label_encoder_multi = self._load_encoder(encoder_path)

    def _load_model(self, model_filename):
        """Load a pickled model file"""
        model_path = os.path.join(self.model_dir, model_filename)
        if os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"Error loading model {model_filename}: {e}")
                # Avoid flashing here, handle in routes if needed
        else:
            print(f"Model file not found: {model_path}")
        return None

    def _load_encoder(self, encoder_path):
        """Load the label encoder"""
        if os.path.exists(encoder_path):
            try:
                with open(encoder_path, "rb") as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"Error loading label encoder: {e}")
        else:
            print(f"Label encoder file not found: {encoder_path}")
        return None

    def classify_log_entry(self, log_entry):
        """Classify a single log entry using the ML model."""
        if not self.parser:
             print("Classifier parser not initialized.")
             return None
             
        feature_dict = self.parser.parse_log_entry(log_entry)
        if not feature_dict:
            return None

        try:
            if not hasattr(self.parser, 'feature_names') or not self.parser.feature_names:
                 print("Error: Parser feature names not available.")
                 return None
            features_ordered = [feature_dict.get(name, 0.0) for name in self.parser.feature_names]
            features_np = np.array(features_ordered).reshape(1, -1)
        except Exception as e:
            print(f"Error preparing feature vector: {e}")
            return None

        binary_pred_label = "Error"
        binary_confidence = 0.0
        multi_pred_label = "Error"
        multi_confidence = 0.0

        if self.model_binary:
            try:
                binary_pred_proba = self.model_binary.predict_proba(features_np)[0]
                binary_pred_label = int(self.model_binary.classes_[np.argmax(binary_pred_proba)])
                binary_confidence = float(np.max(binary_pred_proba))
            except Exception as e:
                print(f"Error during binary prediction: {e}")
        else:
            print("Binary model not loaded.")

        if self.model_multi and self.label_encoder_multi:
            try:
                multi_pred_proba = self.model_multi.predict_proba(features_np)[0]
                multi_pred_index = np.argmax(multi_pred_proba)
                multi_pred_label = self.label_encoder_multi.inverse_transform([multi_pred_index])[0]
                multi_confidence = float(np.max(multi_pred_proba))
            except Exception as e:
                print(f"Error during multi-class prediction: {e}")
        else:
            print("Multi-class model or encoder not loaded.")

        return {
            "binary_label": binary_pred_label,
            "binary_confidence": binary_confidence,
            "multi_label": multi_pred_label,
            "multi_confidence": multi_confidence
        }

# Initialize classifier globally
try:
    classifier = WebSuricataClassifier()
except Exception as e:
    print(f"FATAL: Could not initialize WebSuricataClassifier: {e}")
    classifier = None 

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route("/")
def index():
    return redirect(url_for("home"))

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('sentry_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@app.route("/sentry-dashboard")
@login_required
def sentry_dashboard():
    # Get the count of active hosts (files in the hosts directory)
    try:
        host_files = [os.path.basename(f) for f in glob.glob(os.path.join(HOSTS_DIR, "*.json"))]
        active_hosts_count = len(host_files) - 1  # Subtract 1 to exclude output_predictions.json
        if active_hosts_count < 0:
            active_hosts_count = 0
    except Exception as e:
        print(f"Error counting host files: {e}")
        active_hosts_count = 0
    
    # Get the current date
    current_date = datetime.datetime.now().strftime("%A, %B %d, %Y")
    
    # Load data from output_predictions.json
    dashboard_data = {}
    try:
        predictions_file = os.path.join(HOSTS_DIR, "output_predictions.json")
        if os.path.exists(predictions_file):
            with open(predictions_file, 'r') as f:
                predictions = json.load(f)
                
            # Process the data for the dashboard
            dashboard_data = process_dashboard_data(predictions)
    except Exception as e:
        print(f"Error loading predictions data: {e}")
        dashboard_data = {}
    
    return render_template("sentry_dashboard.html", 
                           active_hosts_count=active_hosts_count,
                           current_date=current_date,
                           dashboard_data=dashboard_data)

def process_dashboard_data(predictions):
    """Process the predictions data for the dashboard"""
    result = {
        'total_events': len(predictions),
        'malicious_count': 0,
        'benign_count': 0,
        'attack_types': {},
        'top_ips': {},
        'recent_events': [],
        'alerts': []
    }
    
    # IP tracking
    source_ips = {}
    dest_ips = {}
    
    # Process each prediction
    for event in predictions:
        # Count malicious vs benign
        if 'classification' in event and 'binary_label' in event['classification']:
            if event['classification']['binary_label'] == 1:
                result['malicious_count'] += 1
                
                # Track attack types
                attack_type = event.get('alert_signature', 'Unknown')
                if attack_type in result['attack_types']:
                    result['attack_types'][attack_type] += 1
                else:
                    result['attack_types'][attack_type] = 1
                    
                # Add to alerts if it's a recent malicious event (first 10)
                if len(result['alerts']) < 10:
                    alert = {
                        'message': f"Detected {attack_type} from {event.get('src_ip', 'unknown')}",
                        'time': event.get('@timestamp', 'unknown time')
                    }
                    result['alerts'].append(alert)
            else:
                result['benign_count'] += 1
        
        # Track source IPs
        src_ip = event.get('src_ip')
        if src_ip:
            if src_ip in source_ips:
                source_ips[src_ip] += 1
            else:
                source_ips[src_ip] = 1
        
        # Track destination IPs
        dest_ip = event.get('dest_ip')
        if dest_ip:
            if dest_ip in dest_ips:
                dest_ips[dest_ip] += 1
            else:
                dest_ips[dest_ip] = 1
        
        # Add to recent events (first 100)
        if len(result['recent_events']) < 100:
            result['recent_events'].append(event)
    
    # Get top source IPs
    top_source_ips = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    # Get top destination IPs
    top_dest_ips = sorted(dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Combine and sort
    all_top_ips = top_source_ips + top_dest_ips
    all_top_ips = sorted(all_top_ips, key=lambda x: x[1], reverse=True)[:10]
    result['top_ips'] = dict(all_top_ips)
    
    # Sort attack types by count
    result['attack_types'] = dict(sorted(result['attack_types'].items(), key=lambda x: x[1], reverse=True)[:5])
    
    # Calculate traffic summary (simplified for demo)
    result['traffic_summary'] = {
        'labels': ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
        'benign': [
            result['benign_count'] // 6,
            result['benign_count'] // 6,
            result['benign_count'] // 6,
            result['benign_count'] // 6,
            result['benign_count'] // 6,
            result['benign_count'] // 6
        ],
        'malicious': [
            result['malicious_count'] // 6,
            result['malicious_count'] // 6,
            result['malicious_count'] // 6,
            result['malicious_count'] // 6,
            result['malicious_count'] // 6,
            result['malicious_count'] // 6
        ]
    }
    
    return result

@app.route("/select_host", methods=["GET"])
def select_host():
    host_files = []
    try:
        host_files = [os.path.basename(f) for f in glob.glob(os.path.join(HOSTS_DIR, "*.json"))]
        host_files.sort()
    except Exception as e:
        flash(f"Error reading host files: {e}", "error")
        print(f"Error listing host files: {e}")
    active_file_id = session.get("file_id")
    return render_template("select_host.html", host_files=host_files, file_id=active_file_id)

@app.route("/process_host", methods=["POST"])
def process_host_file():
    selected_file = request.form.get("host_file")
    if not selected_file:
        flash("No host file selected.", "warning")
        return redirect(url_for("select_host"))

    filepath = os.path.join(HOSTS_DIR, selected_file)
    if not (os.path.exists(filepath) and os.path.isfile(filepath) and os.path.dirname(os.path.abspath(filepath)) == os.path.abspath(HOSTS_DIR)):
        flash(f"Selected file '{selected_file}' not found or is invalid.", "error")
        return redirect(url_for("select_host"))

    safe_filename_id = selected_file.replace(".", "_").replace("/", "_").replace("\\", "_")
    file_id = f"host_{safe_filename_id}_{int(time.time())}"
    
    if file_id in processing_status: del processing_status[file_id]
    if file_id in processed_results: del processed_results[file_id]
        
    processing_status[file_id] = {
        "filename": selected_file,
        "filepath": filepath,
        "total_lines": 0,
        "processed_lines": 0,
        "status": "initializing",
        "malicious_count": 0,
        "benign_count": 0,
        "source": "host",
        "error_message": None
    }

    session["file_id"] = file_id
    thread = threading.Thread(target=process_file_background, args=(filepath, file_id, selected_file))
    thread.daemon = True
    thread.start()
    return redirect(url_for("processing_status_page", file_id=file_id))


@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    active_file_id = session.get("file_id")
    
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part in the request.", "error")
            return redirect(request.url)
        
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected for upload.", "warning")
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            
            if os.path.exists(filepath):
                 flash(f"File '{filename}' already exists in upload folder. Please rename or remove.", "warning")
                 return redirect(request.url)
                 
            try:
                file.save(filepath)
            except Exception as e:
                flash(f"Error saving uploaded file: {e}", "error")
                print(f"Error saving file {filepath}: {e}")
                return redirect(request.url)
            
            file_id = f"upload_{filename.replace('.', '_')}_{int(time.time())}"
            
            if file_id in processing_status: del processing_status[file_id]
            if file_id in processed_results: del processed_results[file_id]

            processing_status[file_id] = {
                "filename": filename,
                "filepath": filepath,
                "total_lines": 0,
                "processed_lines": 0,
                "status": "initializing",
                "malicious_count": 0,
                "benign_count": 0,
                "source": "upload",
                "error_message": None
            }
            
            session["file_id"] = file_id
            thread = threading.Thread(target=process_file_background, args=(filepath, file_id, filename))
            thread.daemon = True
            thread.start()
            return redirect(url_for("processing_status_page", file_id=file_id))
        else:
            flash("Invalid file type. Only .json files are allowed.", "warning")
            return redirect(request.url)
    
    return render_template("index.html", file_id=active_file_id)

# Background file processing task (with merged classification logic)
def process_file_background(filepath, file_id, display_filename):
    global processed_results, processing_status
    results = []
    malicious_count = 0
    benign_count = 0
    processed_lines = 0
    
    if not classifier:
        processing_status[file_id]["status"] = "error"
        processing_status[file_id]["error_message"] = "Classifier not initialized."
        print(f"Aborting processing for {file_id}: Classifier not initialized.")
        return
        
    try:
        if not os.path.exists(filepath):
             raise FileNotFoundError(f"File not found at path: {filepath}")

        total_lines = 0
        try:
            with open(filepath, "rb") as f:
                total_lines = sum(1 for _ in f)
        except Exception as e:
             print(f"Error counting lines in {filepath}: {e}")
             raise IOError(f"Could not read file to count lines: {e}")
             
        processing_status[file_id]["total_lines"] = total_lines
        processing_status[file_id]["status"] = "processing"
        print(f"Starting processing for {file_id}: {display_filename} ({total_lines} lines)")

        with open(filepath, "r", encoding="utf-8", errors="replace") as infile:
            for i, line in enumerate(infile):
                processed_lines = i + 1
                try:
                    line_stripped = line.strip()
                    if not line_stripped: continue 
                        
                    log_entry = json.loads(line_stripped)
                    # Get model classification first
                    classification = classifier.classify_log_entry(log_entry)
                    
                    if classification:
                        # Extract alert info
                        alert_info = log_entry.get("alert", {})
                        alert_signature = alert_info.get("signature")
                        alert_category = alert_info.get("category")
                        alert_severity = alert_info.get("severity")

                        # --- Apply Heuristic from Short Version --- 
                        if alert_signature:
                            # Override model: If alert exists, it's malicious
                            classification["binary_label"] = 1
                            classification["binary_confidence"] = 1.0
                            # Make multi-label more informative
                            classification["multi_label"] = f"Malicious (Alert: {alert_signature})"
                            classification["multi_confidence"] = 1.0
                        # --- End Heuristic --- 

                        # Count based on the FINAL binary label (potentially overridden)
                        final_binary_label = classification.get("binary_label", "Error")
                        if final_binary_label == 1:
                            malicious_count += 1
                        elif final_binary_label == 0:
                            benign_count += 1

                        # Store the result entry with the potentially modified classification
                        result_entry = {
                            "timestamp": log_entry.get("timestamp"),
                            "src_ip": log_entry.get("src_ip"),
                            "src_port": log_entry.get("src_port"),
                            "dest_ip": log_entry.get("dest_ip"),
                            "dest_port": log_entry.get("dest_port"),
                            "proto": log_entry.get("proto"),
                            "event_type": log_entry.get("event_type"),
                            "alert_signature": alert_signature,
                            "alert_category": alert_category,
                            "alert_severity": alert_severity,
                            "classification": classification # Store the final classification dict
                        }
                        results.append(result_entry)
                        
                except json.JSONDecodeError:
                    print(f"Warning: Skipping invalid JSON line {processed_lines} in {display_filename}")
                    continue 
                except Exception as e:
                    print(f"Error processing line {processed_lines} in {display_filename}: {e}")
                
                # Update progress status periodically
                if processed_lines % 100 == 0 or processed_lines == total_lines:
                    processing_status[file_id]["processed_lines"] = processed_lines
                    processing_status[file_id]["malicious_count"] = malicious_count
                    processing_status[file_id]["benign_count"] = benign_count
                    time.sleep(0.01)
                    
        processing_status[file_id]["processed_lines"] = processed_lines
        processing_status[file_id]["malicious_count"] = malicious_count
        processing_status[file_id]["benign_count"] = benign_count
        processed_results[file_id] = results
        processing_status[file_id]["status"] = "completed"
        print(f"Processing completed for {file_id}: {display_filename}")
        
    except FileNotFoundError as e:
        print(f"Error processing file {display_filename} ({file_id}): {e}")
        processing_status[file_id]["status"] = "error"
        processing_status[file_id]["error_message"] = str(e)
    except IOError as e:
        print(f"IO Error processing file {display_filename} ({file_id}): {e}")
        processing_status[file_id]["status"] = "error"
        processing_status[file_id]["error_message"] = f"IO Error: {e}"
    except Exception as e:
        print(f"Unexpected error processing file {display_filename} ({file_id}): {e}")
        processing_status[file_id]["status"] = "error"
        processing_status[file_id]["error_message"] = f"An unexpected error occurred: {e}"
        processing_status[file_id]["processed_lines"] = processed_lines


@app.route("/processing/<file_id>")
def processing_status_page(file_id):
    if file_id not in processing_status:
        flash("Processing session not found or expired.", "error")
        return redirect(url_for("select_host"))
    
    display_filename = processing_status[file_id].get("filename", "Unknown File")
    return render_template("processing.html", file_id=file_id, filename=display_filename)

@app.route("/status/<file_id>")
def get_status(file_id):
    if file_id not in processing_status:
        return jsonify({"status": "not_found", "error_message": "Processing session ID not found."}), 404
    
    return jsonify(dict(processing_status[file_id]))

@app.route("/results/<file_id>")
def show_results(file_id):
    if file_id not in processing_status:
        flash("Results not found for this session ID.", "error")
        return redirect(url_for("select_host"))

    status_info = processing_status[file_id]
    display_filename = status_info.get("filename", "Unknown File")

    if status_info["status"] == "error":
        error_msg = status_info.get("error_message", "Unknown error during processing.")
        flash(f"Error processing file '{display_filename}': {error_msg}", "error")
        return redirect(url_for("select_host"))
        
    if status_info["status"] != "completed":
        flash(f"Processing for '{display_filename}' is not yet complete. Redirecting to status page.", "info")
        return redirect(url_for("processing_status_page", file_id=file_id))
    
    if file_id not in processed_results:
         flash("Processed results data is missing, even though status is complete.", "error")
         return redirect(url_for("select_host"))

    results_data = processed_results[file_id]
    malicious_count = status_info.get("malicious_count", 0)
    benign_count = status_info.get("benign_count", 0)
    total_count = malicious_count + benign_count

    session["file_id"] = file_id 

    return render_template("results.html", 
                           results=results_data, 
                           filename=display_filename,
                           file_id=file_id,
                           stats={
                               "malicious_count": malicious_count,
                               "benign_count": benign_count,
                               "total_count": total_count
                           })

@app.route("/dashboard/<file_id>")
def dashboard(file_id):
    if file_id not in processing_status or processing_status[file_id]["status"] != "completed":
        flash("Dashboard requires completed analysis. Please process the file first.", "warning")
        return redirect(url_for("show_results", file_id=file_id))

    if file_id not in processed_results:
        flash("Processed results data not found for dashboard.", "error")
        return redirect(url_for("select_host"))
        
    display_filename = processing_status[file_id].get("filename", "Unknown File")
    return render_template("dashboard.html", file_id=file_id, filename=display_filename)

@app.route("/dashboard-data/<file_id>")
def dashboard_data(file_id):
    if file_id not in processed_results:
        return jsonify({"error": "Results not found"}), 404
        
    results_data = processed_results[file_id]
    return jsonify({"results": results_data})


@app.route("/monitor/<filename>")
def monitor(filename):
    safe_filename = secure_filename(filename)
    if safe_filename != filename:
        flash("Invalid filename for monitoring.", "error")
        return redirect(url_for("select_host"))
        
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], safe_filename)
    if not os.path.exists(filepath):
         flash(f"Cannot monitor non-existent file in uploads: {safe_filename}", "error")
         return redirect(url_for("upload_file"))
         
    active_file_id = session.get("file_id")
    return render_template("monitor.html", filename=safe_filename, file_id=active_file_id)

@app.route("/stream/<filename>")
def stream(filename):
    safe_filename = secure_filename(filename)
    if safe_filename != filename:
        return Response("Invalid filename", status=400)
        
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], safe_filename)
    if not os.path.exists(filepath):
        return Response("File not found", status=404)
        
    def generate():
        if not classifier:
            yield f"data: {json.dumps({'error': 'Classifier not available'})}\n\n"
            return
            
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                        
                    try:
                        log_entry = json.loads(line_stripped)
                        classification = classifier.classify_log_entry(log_entry)
                        
                        if classification:
                             # Apply the same heuristic for streaming
                             alert_signature = log_entry.get("alert", {}).get("signature")
                             if alert_signature:
                                 classification["binary_label"] = 1
                                 classification["binary_confidence"] = 1.0
                                 classification["multi_label"] = f"Malicious (Alert: {alert_signature})"
                                 classification["multi_confidence"] = 1.0

                             alert_info = log_entry.get("alert", {})
                             stream_data = {
                                "timestamp": log_entry.get("timestamp"),
                                "src_ip": log_entry.get("src_ip"),
                                "dest_ip": log_entry.get("dest_ip"),
                                "proto": log_entry.get("proto"),
                                "event_type": log_entry.get("event_type"),
                                "alert_signature": alert_info.get("signature"),
                                "classification": classification
                            }
                             yield f"data: {json.dumps(stream_data)}\n\n"
                             
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        print(f"Error processing stream line: {e}")
                        
        except Exception as e:
            print(f"Error in stream generator for {safe_filename}: {e}")
            yield f"data: {json.dumps({'error': f'Stream error: {e}'})}\n\n"

    return Response(generate(), mimetype="text/event-stream")

@app.context_processor
def inject_active_file_id():
    return dict(active_file_id=session.get('file_id'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

