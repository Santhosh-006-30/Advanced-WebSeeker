
from flask import Flask, render_template, request, jsonify, Response, send_file
import threading
import queue
import time
import json
import os
from core.engine import ScannerEngine

app = Flask(__name__)

# Global state
scan_state = {
    "is_running": False,
    "progress": 0,
    "result": None
}
# Using a list of queues for multiple potential listeners (browser tabs)
listeners = []

def broadcast_message(data):
    for q in listeners[:]:
        try:
            q.put(data)
        except queue.Full:
            listeners.remove(q)

def scan_worker(url):
    global scan_state
    scan_state["is_running"] = True
    scan_state["progress"] = 0
    scan_state["result"] = None

    def callback(type, message):
        timestamp = time.strftime("%H:%M:%S")
        
        if type == 'progress':
            try:
                prog_val = int(message)
                scan_state["progress"] = prog_val
                # Only broadcast progress if it changes significantly or just throttle in frontend
                broadcast_message(f"data: {json.dumps({'type': 'progress', 'value': prog_val})}\n\n")
            except:
                pass
        else:
            # Info/Error/Success
            data = {
                'type': 'log',
                'level': type,
                'message': f"[{timestamp}] {message}"
            }
            broadcast_message(f"data: {json.dumps(data)}\n\n")

    try:
        engine = ScannerEngine(output_callback=callback)
        results = engine.run_scan(url)
        scan_state["result"] = results
        # Send completion event
        broadcast_message(f"data: {json.dumps({'type': 'complete', 'results': results})}\n\n")
    except Exception as e:
        broadcast_message(f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n")
    finally:
        scan_state["is_running"] = False
        scan_state["progress"] = 100
        broadcast_message(f"data: {json.dumps({'type': 'progress', 'value': 100})}\n\n")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    if scan_state["is_running"]:
        return jsonify({"status": "error", "message": "Scan is already in progress."})
    
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"status": "error", "message": "URL is required."})

    thread = threading.Thread(target=scan_worker, args=(url,))
    thread.daemon = True
    thread.start()
    return jsonify({"status": "success"})

@app.route('/stream')
def stream():
    def event_stream():
        q = queue.Queue(maxsize=100)
        listeners.append(q)
        try:
            while True:
                try:
                    msg = q.get(timeout=20)
                    yield msg
                except queue.Empty:
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            listeners.remove(q)

    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/reports/<path:filename>')
def download_report(filename):
    # Ideally should be in a reports folder, but currently main.py saves to root mostly
    # We should allow serving the generated html
    return send_file(filename)

if __name__ == '__main__':
    print("Starting Web Fuzzer UI at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
