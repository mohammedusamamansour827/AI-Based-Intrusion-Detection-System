#!/usr/bin/env python3
"""
Parses Suricata eve.json logs and extracts features for ML classification.

Includes enhanced features for detecting port scans and other activities.
"""

import json
import time
import os
import pickle
import numpy as np
from collections import defaultdict, deque

class SuricataLogParser:
    def __init__(self, model_dir, window_size_seconds=5):
        """
        Initializes the parser, loads feature names, and sets up state tracking.

        Args:
            model_dir (str): Directory containing model-related files (like feature names).
            window_size_seconds (int): Time window (in seconds) for tracking recent activity 
                                       (e.g., unique ports per source).
        """
        self.model_dir = model_dir
        self.window_size_seconds = window_size_seconds
        self.feature_names = self._load_feature_names()
        self.scaler = self._load_scaler()
        
        # State tracking for flow aggregation and enhanced features
        self.flow_records = {}
        self.recent_activity = defaultdict(lambda: {
            "timestamps": deque(),
            "dest_ports": deque(),
            "syn_count": 0,
            "conn_attempts": 0
        })
        self.protocol_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
        self.tcp_flags = ["syn", "fin", "rst", "psh", "ack", "urg"]

    def _load_feature_names(self):
        """Loads the list of feature names the model expects."""
        # Try loading from the original binary model first as a base
        feature_file = os.path.join(self.model_dir, "feature_names_binary.pkl")
        if not os.path.exists(feature_file):
             # Fallback if the specific binary file isn't there (e.g., during retraining setup)
             feature_file = os.path.join(self.model_dir, "feature_names.pkl")
             if not os.path.exists(feature_file):
                 print("Warning: Feature names file not found in model directory. Using default list.")
                 # Define a default list if none is found - MUST match training
                 # Adding new features here!
                 default_features = [
                    "duration", "proto_numeric", "service_http", "service_dns", "service_tls", "service_ssh",
                    "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
                    "flow_state_established", "flow_state_new", "flow_state_closed",
                    "alert_severity_1", "alert_severity_2", "alert_severity_3",
                    # New TCP Flag Features
                    "tcp_flag_syn", "tcp_flag_fin", "tcp_flag_rst", "tcp_flag_psh", "tcp_flag_ack", "tcp_flag_urg",
                    # New Rate/Scan Features (calculated over window)
                    "src_conn_rate_window", "src_unique_dest_ports_window", "src_syn_rate_window"
                 ]
                 # Save this default list for consistency if needed later
                 os.makedirs(self.model_dir, exist_ok=True)
                 save_path = os.path.join(self.model_dir, "feature_names.pkl")
                 try:
                     with open(save_path, "wb") as f:
                         pickle.dump(default_features, f)
                     print(f"Saved default feature list to {save_path}")
                 except Exception as e:
                     print(f"Error saving default feature list: {e}")
                 return default_features
                 
        try:
            with open(feature_file, "rb") as f:
                features = pickle.load(f)
                # --- Add new features if they don't exist --- 
                # This ensures compatibility if loading an older feature list
                new_features_to_add = [
                    "tcp_flag_syn", "tcp_flag_fin", "tcp_flag_rst", "tcp_flag_psh", "tcp_flag_ack", "tcp_flag_urg",
                    "src_conn_rate_window", "src_unique_dest_ports_window", "src_syn_rate_window"
                ]
                updated = False
                for feat in new_features_to_add:
                    if feat not in features:
                        features.append(feat)
                        updated = True
                
                if updated:
                    print("Updated feature list with new features.")
                    # Optionally re-save the updated list
                    try:
                        with open(feature_file, "wb") as f:
                            pickle.dump(features, f)
                        print(f"Saved updated feature list to {feature_file}")
                    except Exception as e:
                        print(f"Error saving updated feature list: {e}")
                # --- End of adding new features --- 
                print(f"Loaded {len(features)} feature names from {feature_file}")
                return features
        except Exception as e:
            print(f"Error loading feature names from {feature_file}: {e}. Using default list.")
            # Fallback to default if loading fails
            return self._load_feature_names() # Recurse to get default

    def _load_scaler(self):
        """Loads the scaler object if it exists."""
        scaler_file = os.path.join(self.model_dir, "scaler.pkl")
        if os.path.exists(scaler_file):
            try:
                with open(scaler_file, "rb") as f:
                    print("Scaler found and loaded.")
                    return pickle.load(f)
            except Exception as e:
                print(f"Error loading scaler: {e}. Proceeding without scaler.")
        else:
            print("Warning: Scaler not found. Features will not be normalized.")
        return None

    def _update_recent_activity(self, src_ip, dest_port, timestamp_str, is_syn):
        """Updates the recent activity tracker for a given source IP."""
        try:
            # Convert timestamp string to Unix timestamp (float)
            # Handle potential timezone offsets (+0300)
            if '+' in timestamp_str:
                base_time, tz_offset = timestamp_str.split('+')
                # Simple approach: parse base time, ignore TZ for window calculation
                # More robust: use dateutil.parser or handle TZ properly if needed
                dt_obj = time.strptime(base_time, "%Y-%m-%dT%H:%M:%S.%f")
                timestamp = time.mktime(dt_obj)
            else:
                 # Assume UTC or local time if no offset
                 dt_obj = time.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
                 timestamp = time.mktime(dt_obj)
        except ValueError:
             # Fallback for different timestamp formats if necessary
             try:
                 dt_obj = time.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S") # Without microseconds
                 timestamp = time.mktime(dt_obj)
             except ValueError:
                 print(f"Warning: Could not parse timestamp {timestamp_str}. Skipping activity update.")
                 return

        activity = self.recent_activity[src_ip]
        current_time = timestamp

        # Remove entries older than the window size
        while activity["timestamps"] and current_time - activity["timestamps"][0] > self.window_size_seconds:
            activity["timestamps"].popleft()
            activity["dest_ports"].popleft()
            # Note: We don't perfectly track which SYN belongs to popped timestamp, 
            # so syn_count becomes an approximation over the window.
            # A more complex structure would be needed for exact SYN tracking per entry.

        # Add current entry
        activity["timestamps"].append(current_time)
        activity["dest_ports"].append(dest_port)
        activity["conn_attempts"] = len(activity["timestamps"])
        if is_syn:
            activity["syn_count"] += 1 # Increment SYN count for this source
            
        # Prune SYN count if window is empty (to avoid infinite growth)
        if not activity["timestamps"]:
             activity["syn_count"] = 0
             
    def _get_recent_activity_features(self, src_ip):
        """Calculates features based on recent activity for a source IP."""
        activity = self.recent_activity[src_ip]
        num_connections = activity["conn_attempts"]
        
        if not num_connections or not activity["timestamps"]:
            return 0.0, 0, 0.0 # Rate, Unique Ports, SYN Rate

        # Calculate time span of the current window
        time_span = max(1, activity["timestamps"][-1] - activity["timestamps"][0]) # Avoid division by zero, min 1 sec span
        
        connection_rate = num_connections / time_span
        unique_ports = len(set(activity["dest_ports"]))
        # Approximate SYN rate over the window
        syn_rate = activity["syn_count"] / time_span 
        
        # Simple cleanup: if window shrinks significantly, reset syn_count to avoid artificially high rates
        # This is an approximation; better tracking might be needed for high accuracy.
        if num_connections < activity["syn_count"]:
             activity["syn_count"] = sum(1 for t, p, is_s in zip(activity["timestamps"], activity["dest_ports"], [True]*activity["syn_count"]) if is_s) # Recalculate if needed
             if activity["syn_count"] == 0 and num_connections > 0: # Reset if inconsistent
                 activity["syn_count"] = 0
                 syn_rate = 0.0
             elif time_span > 0: 
                 syn_rate = activity["syn_count"] / time_span
             else: 
                 syn_rate = 0.0
                 
        # Cap SYN count at number of connections if logic gets skewed
        activity["syn_count"] = min(activity["syn_count"], num_connections)
        if time_span > 0:
            syn_rate = activity["syn_count"] / time_span
        else: 
            syn_rate = 0.0

        return connection_rate, unique_ports, syn_rate

    def parse_log_entry(self, log_entry):
        """
        Parses a single Suricata log entry (as a dictionary) and extracts features.
        Handles different event types (flow, alert, dns, http, tls, ssh).
        """
        event_type = log_entry.get("event_type")
        flow_id = log_entry.get("flow_id")

        if flow_id is None:
            return None # Cannot process without flow context

        # Initialize or retrieve flow record
        if flow_id not in self.flow_records:
            self.flow_records[flow_id] = {
                "features": defaultdict(float),
                "start_time": None,
                "end_time": None,
                "has_alert": False,
                "alert_severity": 0,
                "protocol": log_entry.get("proto"),
                "src_ip": log_entry.get("src_ip"),
                "dest_ip": log_entry.get("dest_ip"),
                "src_port": log_entry.get("src_port"),
                "dest_port": log_entry.get("dest_port"),
                "tcp_flags_set": set() # Store unique TCP flags seen for the flow
            }
        
        record = self.flow_records[flow_id]
        features = record["features"]
        timestamp_str = log_entry.get("timestamp")

        # Update start/end times
        try:
            # Attempt parsing with timezone offset first
            if '+' in timestamp_str:
                base_time, _ = timestamp_str.split('+')
                current_time = time.mktime(time.strptime(base_time, "%Y-%m-%dT%H:%M:%S.%f"))
            else:
                current_time = time.mktime(time.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f"))
            
            if record["start_time"] is None or current_time < record["start_time"]:
                record["start_time"] = current_time
            if record["end_time"] is None or current_time > record["end_time"]:
                record["end_time"] = current_time
        except (ValueError, TypeError):
             # Fallback for different timestamp formats or if timestamp is missing
             try:
                 if '+' in timestamp_str:
                     base_time, _ = timestamp_str.split('+')
                     current_time = time.mktime(time.strptime(base_time, "%Y-%m-%dT%H:%M:%S"))
                 else:
                     current_time = time.mktime(time.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S"))
                 if record["start_time"] is None or current_time < record["start_time"]:
                     record["start_time"] = current_time
                 if record["end_time"] is None or current_time > record["end_time"]:
                     record["end_time"] = current_time
             except (ValueError, TypeError):
                 pass # Ignore if timestamp is unparseable

        # --- Extract features based on event type --- 
        is_syn = False # Flag to track if this specific log entry involves a SYN
        if event_type == "flow":
            flow_data = log_entry.get("flow", {})
            record["protocol"] = log_entry.get("proto", record["protocol"])
            record["src_ip"] = log_entry.get("src_ip", record["src_ip"])
            record["dest_ip"] = log_entry.get("dest_ip", record["dest_ip"])
            record["src_port"] = log_entry.get("src_port", record["src_port"])
            record["dest_port"] = log_entry.get("dest_port", record["dest_port"])
            
            features["pkts_toserver"] = flow_data.get("pkts_toserver", 0)
            features["pkts_toclient"] = flow_data.get("pkts_toclient", 0)
            features["bytes_toserver"] = flow_data.get("bytes_toserver", 0)
            features["bytes_toclient"] = flow_data.get("bytes_toclient", 0)
            
            state = flow_data.get("state", "").lower()
            features["flow_state_established"] = 1 if state == "established" else 0
            features["flow_state_new"] = 1 if state == "new" else 0
            features["flow_state_closed"] = 1 if state == "closed" else 0
            
            # Record TCP flags from flow event if available
            tcp_flags_str = flow_data.get("tcp_flags_ts", "") + flow_data.get("tcp_flags_tc", "")
            for flag in self.tcp_flags:
                if flag in tcp_flags_str.lower():
                    record["tcp_flags_set"].add(flag)
                    if flag == 'syn':
                        is_syn = True

        elif event_type == "alert":
            alert_data = log_entry.get("alert", {})
            record["has_alert"] = True
            severity = alert_data.get("severity", 0)
            # Use max severity seen for the flow
            record["alert_severity"] = max(record["alert_severity"], severity)
            # Capture flags from alert context if available (might be in flow sub-object)
            flow_data = log_entry.get("flow", {})
            tcp_flags_str = flow_data.get("tcp_flags_ts", "") + flow_data.get("tcp_flags_tc", "")
            for flag in self.tcp_flags:
                if flag in tcp_flags_str.lower():
                    record["tcp_flags_set"].add(flag)
                    if flag == 'syn':
                        is_syn = True
                        
        elif event_type == "netflow": # Sometimes flow stats are here
            netflow_data = log_entry.get("netflow", {})
            record["protocol"] = netflow_data.get("proto", record["protocol"])
            record["src_ip"] = netflow_data.get("src_ip", record["src_ip"])
            record["dest_ip"] = netflow_data.get("dest_ip", record["dest_ip"])
            record["src_port"] = netflow_data.get("src_port", record["src_port"])
            record["dest_port"] = netflow_data.get("dest_port", record["dest_port"])
            features["pkts_toserver"] = max(features["pkts_toserver"], netflow_data.get("pkts", 0)) # Approx
            features["bytes_toserver"] = max(features["bytes_toserver"], netflow_data.get("bytes", 0)) # Approx
            if record["start_time"] is None: record["start_time"] = netflow_data.get("flow_start_sec")
            record["end_time"] = max(record.get("end_time", 0), netflow_data.get("flow_end_sec", 0))
            
        elif event_type == "http":
            features["service_http"] = 1
        elif event_type == "dns":
            # Could add features like query type, length, entropy here
            features["service_dns"] = 1
        elif event_type == "tls":
            # Could add JA3/JA3S, cert info here
            features["service_tls"] = 1
        elif event_type == "ssh":
            features["service_ssh"] = 1
        elif event_type == "tcp": # Capture TCP flags from tcp events
             tcp_data = log_entry.get("tcp", {})
             tcp_flags_str = tcp_data.get("flags", "")
             for flag in self.tcp_flags:
                 if flag in tcp_flags_str.lower():
                     record["tcp_flags_set"].add(flag)
                     if flag == 'syn':
                         is_syn = True

        # --- Update recent activity for the source IP --- 
        if record["src_ip"] and record["dest_port"] and timestamp_str:
            self._update_recent_activity(record["src_ip"], record["dest_port"], timestamp_str, is_syn)

        # --- Final feature calculation for the flow (when called) --- 
        # This part assumes we call parse_log_entry repeatedly and then finalize
        # For real-time, we might return features based on current state
        
        # Calculate duration
        if record["start_time"] and record["end_time"]:
            features["duration"] = max(0, record["end_time"] - record["start_time"])
        else:
            features["duration"] = 0
            
        # Protocol
        features["proto_numeric"] = self.protocol_map.get(record["protocol"], 0)
        
        # Alert Severity (one-hot encode)
        severity = record["alert_severity"]
        features["alert_severity_1"] = 1 if severity == 1 else 0
        features["alert_severity_2"] = 1 if severity == 2 else 0
        features["alert_severity_3"] = 1 if severity == 3 else 0 # Assuming severity 3 is max relevant

        # TCP Flags (one-hot encode based on flags seen in the flow)
        for flag in self.tcp_flags:
            features[f"tcp_flag_{flag}"] = 1 if flag in record["tcp_flags_set"] else 0
            
        # Recent Activity Features
        if record["src_ip"]:
            conn_rate, unique_ports, syn_rate = self._get_recent_activity_features(record["src_ip"])
            features["src_conn_rate_window"] = conn_rate
            features["src_unique_dest_ports_window"] = unique_ports
            features["src_syn_rate_window"] = syn_rate
        else:
            features["src_conn_rate_window"] = 0.0
            features["src_unique_dest_ports_window"] = 0
            features["src_syn_rate_window"] = 0.0

        # --- Create final feature vector --- 
        # Ensure all expected features are present, default to 0.0
        feature_vector = [features.get(name, 0.0) for name in self.feature_names]
        
        # Apply scaler if loaded
        if self.scaler:
            try:
                # Scaler expects a 2D array
                feature_vector_np = np.array(feature_vector).reshape(1, -1)
                scaled_features = self.scaler.transform(feature_vector_np)
                # Return the scaled features as a dictionary
                return dict(zip(self.feature_names, scaled_features[0]))
            except Exception as e:
                print(f"Warning: Error applying scaler: {e}. Returning unscaled features.")
                # Fallback to unscaled if error
                return dict(zip(self.feature_names, feature_vector))
        else:
            # Return unscaled features as a dictionary
            return dict(zip(self.feature_names, feature_vector))

    def cleanup_old_flows(self, current_timestamp, timeout=60):
        """Removes flow records older than the timeout."""
        cutoff_time = current_timestamp - timeout
        flows_to_remove = [flow_id for flow_id, record in self.flow_records.items() 
                           if record.get("end_time", 0) < cutoff_time]
        for flow_id in flows_to_remove:
            del self.flow_records[flow_id]
        # print(f"Cleaned up {len(flows_to_remove)} old flows.") # Optional debug
        
    def cleanup_recent_activity(self, current_timestamp):
        """Cleans up old entries from the recent activity tracker."""
        cutoff_time = current_timestamp - self.window_size_seconds
        ips_to_update = list(self.recent_activity.keys())
        for src_ip in ips_to_update:
            activity = self.recent_activity[src_ip]
            # Remove old entries
            while activity["timestamps"] and activity["timestamps"][0] < cutoff_time:
                activity["timestamps"].popleft()
                activity["dest_ports"].popleft()
                # Note: syn_count is approximate, not perfectly tied to popped entries
                
            # Update counts based on remaining entries
            activity["conn_attempts"] = len(activity["timestamps"])
            if not activity["timestamps"]:
                 activity["syn_count"] = 0 # Reset if empty
            else:
                 # Simple approximation: keep syn_count capped by conn_attempts
                 activity["syn_count"] = min(activity["syn_count"], activity["conn_attempts"])
                 
            # Remove entry if completely empty
            if not activity["timestamps"]:
                del self.recent_activity[src_ip]
                
# Example Usage (for testing)
if __name__ == "__main__":
    # Create dummy model dir and feature file for testing
    test_model_dir = "./temp_model_dir"
    os.makedirs(test_model_dir, exist_ok=True)
    default_features = [
        "duration", "proto_numeric", "service_http", "service_dns", "service_tls", "service_ssh",
        "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
        "flow_state_established", "flow_state_new", "flow_state_closed",
        "alert_severity_1", "alert_severity_2", "alert_severity_3",
        "tcp_flag_syn", "tcp_flag_fin", "tcp_flag_rst", "tcp_flag_psh", "tcp_flag_ack", "tcp_flag_urg",
        "src_conn_rate_window", "src_unique_dest_ports_window", "src_syn_rate_window"
    ]
    with open(os.path.join(test_model_dir, "feature_names.pkl"), "wb") as f:
        pickle.dump(default_features, f)

    parser = SuricataLogParser(model_dir=test_model_dir)
    
    # Example log entries (replace with actual eve.json lines)
    log1 = {"timestamp":"2025-05-23T21:07:10.978202+0300","flow_id":1,"event_type":"alert","src_ip":"192.168.1.10","dest_ip":"192.168.1.20","src_port":12345,"dest_port":80,"proto":"TCP","alert":{"severity":2},"flow":{"tcp_flags_ts":"S"}}
    log2 = {"timestamp":"2025-05-23T21:07:11.178202+0300","flow_id":1,"event_type":"flow","src_ip":"192.168.1.10","dest_ip":"192.168.1.20","src_port":12345,"dest_port":80,"proto":"TCP","flow":{"pkts_toserver":5,"bytes_toserver":500,"state":"established","tcp_flags_tc":"A"}}
    log3 = {"timestamp":"2025-05-23T21:07:11.978202+0300","flow_id":2,"event_type":"dns","src_ip":"192.168.1.10","dest_ip":"8.8.8.8","src_port":54321,"dest_port":53,"proto":"UDP"}
    log4 = {"timestamp":"2025-05-23T21:07:12.178202+0300","flow_id":1,"event_type":"flow","src_ip":"192.168.1.10","dest_ip":"192.168.1.20","src_port":12345,"dest_port":80,"proto":"TCP","flow":{"pkts_toclient":3,"bytes_toclient":300,"state":"closed"}}
    log5 = {"timestamp":"2025-05-23T21:07:12.578202+0300","flow_id":3,"event_type":"alert","src_ip":"192.168.1.10","dest_ip":"192.168.1.21","src_port":12346,"dest_port":22,"proto":"TCP","alert":{"severity":1},"flow":{"tcp_flags_ts":"S"}}
    log6 = {"timestamp":"2025-05-23T21:07:12.878202+0300","flow_id":4,"event_type":"alert","src_ip":"192.168.1.10","dest_ip":"192.168.1.22","src_port":12347,"dest_port":23,"proto":"TCP","alert":{"severity":1},"flow":{"tcp_flags_ts":"S"}}

    features1 = parser.parse_log_entry(log1)
    features2 = parser.parse_log_entry(log2)
    features3 = parser.parse_log_entry(log3)
    features4 = parser.parse_log_entry(log4)
    features5 = parser.parse_log_entry(log5)
    features6 = parser.parse_log_entry(log6)

    print("\n--- Features Extracted ---")
    print("Log 1 (Flow 1 - Alert):", features1)
    print("Log 2 (Flow 1 - Flow):", features2) # Features update for Flow 1
    print("Log 3 (Flow 2 - DNS):", features3)
    print("Log 4 (Flow 1 - Flow Closed):", features4) # Final features for Flow 1
    print("Log 5 (Flow 3 - Alert):", features5)
    print("Log 6 (Flow 4 - Alert):", features6)
    
    # Clean up dummy files
    import shutil
    shutil.rmtree(test_model_dir)
