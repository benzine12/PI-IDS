# routes.py
from flask import Blueprint, jsonify, render_template, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import psutil
from models import User
from data import DB, state, ap_scanner,bcrypt

views = Blueprint('views', __name__)

@views.route('/')
def login_page():
    """ Render the login page """
    return render_template('login.html') 

@views.get('/dashboard')
def dashboard_page():
    """ Render the home page """
    return render_template('dashboard.html')

@views.get('/ap-scan')
def ap_scan_page():
    """ Render the access point scan page """
    return render_template('ap_scan.html')

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
   
#login func
@views.post('/login')
# @func_logger
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
            print(access_token)
            return jsonify({"msg": "Welcome back, commander!",
                        "access_token": access_token}), 200

        return jsonify({"msg": "Invalid username or password",
                        "error": "Something went wrong"}), 401