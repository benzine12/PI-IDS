# routes.py
import logging
from flask import Blueprint, jsonify, redirect, render_template, request
from flask_jwt_extended import create_access_token, jwt_required
import psutil
from models import AP, User
from data import DB, state,bcrypt
from modules import ap_scanner

views = Blueprint('views', __name__)

@views.get('/')
def login_page():
    """ Render the login page """
    return render_template('login.html') 

@views.get('/dashboard')
@jwt_required()
def dashboard():
    """Render the dashboard page with server-side JWT verification"""
    try:
        return render_template('dashboard.html')
    except Exception:
        return redirect('/')

@views.get('/ap-scan')
@jwt_required()
def ap_scan():
    """Render the ap-scan page with server-side JWT verification"""
    try:
        return render_template('ap_scan.html')
    except Exception:
        return redirect('/')

@views.get('/get-aps')
@jwt_required()
def get_aps():
    """ Get the active access points and their statistics """
    try:
        aps = ap_scanner.get_active_aps()
        stats = ap_scanner.get_ap_stats()
        return jsonify({
            "status": "success",
            "access_points": aps,
            "statistics": stats
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@views.get('/packets')
@jwt_required()
def get_packets():
    """ Get the detected packets """
    aggregated_results = {}
    for packet in state.detected_attacks:
        dst_mac = packet["dst_mac"]
        if dst_mac not in aggregated_results:
            aggregated_results[dst_mac] = packet
        else:
            aggregated_results[dst_mac]["count"] = state.attack_counts[dst_mac]

    return jsonify({
        "detected_attacks": list(aggregated_results.values()),
        "total_packets": state.packet_counter,
        "threats": len(state.detected_attacks)
    })
        
@views.get('/system-stats')
@jwt_required()
def system_stats():
    """ Get the system statistics """

    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    cpu = psutil.cpu_percent(interval=0.5)
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as temp_file:
            temp_c = int(temp_file.read().strip()) / 1000.0
    except FileNotFoundError:
        temp_c = None
    return jsonify({
        "status": "ok",
        "memory": {
            "total": round(memory.total / (1024**3), 2),
            "used": round(memory.used / (1024**3), 2),
            "percent": memory.percent,
        },
        "disk": {
            "total": round(disk.total / (1024**3), 2),
            "used": round(disk.used / (1024**3), 2),
            "percent": disk.percent,
        },
        "cpu": {"percent": cpu},
        "temperature": {"celsius": round(temp_c, 2) if temp_c is not None else "N/A"}
    })
   
@views.post('/login')
def login():
    if request.method == 'POST':
        if not request.is_json:
            return jsonify({"msg": "Missing or invalid JSON in request",
                            "error": "Bad request"}), 400

        username = request.json.get('username', None)
        password = request.json.get('password', None)

        if not username or not password:
            return jsonify({"msg": "Username and password are required",
                            "error": "Bad request"}), 400

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=str(user.id))
            # refresh_token = create_refresh_token(identity=username)
            return jsonify({"msg": "Welcome back, commander!",
                        "access_token": access_token}), 200

        return jsonify({"msg": "Invalid username or password",
                        "error": "Something went wrong"}), 401
    
@views.post('/set_to_protected')
@jwt_required()
def set_to_protected():
    if request.method == 'POST':
        if not request.is_json:
            return jsonify({"msg": "Missing or invalid JSON in request",
                            "error": "Bad request"}), 400
        data = request.json
        # Define allowed fields
        allowed_fields = {"bssid", "essid", "band","crypto"}
        unexpected_fields = set(data.keys()) - allowed_fields
        if unexpected_fields:
            return jsonify({"msg": "Missing or invalid JSON in request",
                            "error": "Bad request"}), 400
        # Validate required fields
        if not allowed_fields.issubset(data.keys()):
            return jsonify({"msg": "Missing or invalid JSON in request",
                            "error": "Bad request"}), 400
        
        existing_ap = AP.query.filter_by(bssid=data["bssid"]).first()
        if existing_ap:

            existing_ap.essid = data["essid"]
            existing_ap.band = data["band"] 
            existing_ap.crypto = data["crypto"]

            DB.session.commit()

            return jsonify({"msg": "AP updated successfully"}), 200
        else:

            add_ap = AP(
                bssid = data["bssid"],
                essid = data["essid"],
                band = data["band"],
                crypto = data["crypto"],
            )

            DB.session.add(add_ap)
            DB.session.commit()
            logging.warning(f"Added new AP: BSSID={data['bssid']}, ESSID={data['essid']}")
            return jsonify({"msg": "AP added successfully"}), 201

