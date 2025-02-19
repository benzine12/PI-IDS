from flask import Blueprint, jsonify, render_template
import psutil
from data import attack_counts, packet_counter, ap_scanner, captured_packets

views = Blueprint('views', __name__)

@views.get('/ap-scan')
def ap_scan_page():
    return render_template('ap_scan.html')

@views.get('/get-aps')
def get_aps():
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
def get_packets():
    aggregated_results = {}
    for packet in captured_packets:
        dst_mac = packet["dst_mac"]
        if dst_mac not in aggregated_results:
            aggregated_results[dst_mac] = packet
        else:
            aggregated_results[dst_mac]["count"] = attack_counts[dst_mac]

    return jsonify({
        "packets": list(aggregated_results.values()),
        "total_packets": packet_counter,
        "threats": len(captured_packets)
    })
        
@views.get('/system-stats')
def system_stats():
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

@views.get('/')
def home():
    return render_template('dashboard.html')
