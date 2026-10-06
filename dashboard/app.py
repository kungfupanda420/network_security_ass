from flask import Flask, render_template, jsonify
import sqlite3
import os
from collections import defaultdict, Counter

app = Flask(__name__)

# Path to your SQLite database
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'alerts.db')

def get_db_connection():
    # Connect to DB and return rows as dictionary-like objects
    if not os.path.exists(DB_PATH):
        # Create an empty db file if it doesn't exist yet to prevent crashes
        open(DB_PATH, 'a').close()
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ==========================================
# PAGE ROUTES
# ==========================================

@app.route('/')
def index():
    # Serves the main dashboard (data is loaded via AJAX)
    return render_template('index.html')

@app.route('/events')
def events():
    # Serves the full event log
    conn = get_db_connection()
    try:
        events = conn.execute("SELECT * FROM attacks ORDER BY timestamp DESC").fetchall()
    except sqlite3.OperationalError:
        events = [] # Handle case where table isn't created yet
    conn.close()
    return render_template('events.html', events=events)

@app.route('/attackers')
def attackers():
    # Serves Threat Intel grouped by IP address
    conn = get_db_connection()
    try:
        raw_data = conn.execute("SELECT ip, target_port, risk_level FROM attacks").fetchall()
    except sqlite3.OperationalError:
        raw_data = []
    conn.close()

    # Process data in Python to find the top port and max risk per IP
    ips_data = defaultdict(lambda: {'count': 0, 'ports': Counter(), 'risks': set()})
    
    for row in raw_data:
        ip = row['ip']
        ips_data[ip]['count'] += 1
        ips_data[ip]['ports'][row['target_port']] += 1
        ips_data[ip]['risks'].add(row['risk_level'])

    attackers_list = []
    for ip, data in ips_data.items():
        # Find the most frequently targeted port for this IP
        top_port = data['ports'].most_common(1)[0][0]
        
        # Determine highest risk level reached
        if 'HIGH' in data['risks']: max_risk = 'HIGH'
        elif 'MEDIUM' in data['risks']: max_risk = 'MEDIUM'
        elif 'LOW' in data['risks']: max_risk = 'LOW'
        else: max_risk = 'UNKNOWN'

        attackers_list.append({
            'ip': ip,
            'packet_count': data['count'],
            'top_port': top_port,
            'max_risk': max_risk
        })

    # Sort attackers by packet count (most aggressive first)
    attackers_list = sorted(attackers_list, key=lambda x: x['packet_count'], reverse=True)

    return render_template('attackers.html', attackers=attackers_list)

@app.route('/honeypot')
def honeypot():
    # Serves Honeypot redirection statistics
    conn = get_db_connection()
    try:
        redirects = conn.execute("SELECT * FROM attacks WHERE action='REDIRECT_HONEYPOT' ORDER BY timestamp DESC").fetchall()
    except sqlite3.OperationalError:
        redirects = []
    conn.close()

    # Calculate hits per service
    trapped_count = len(redirects)
    ssh_hits = sum(1 for r in redirects if r['target_port'] == 22)
    ftp_hits = sum(1 for r in redirects if r['target_port'] == 21)
    http_hits = trapped_count - ssh_hits - ftp_hits # Everything else defaults to HTTP

    return render_template('honeypot.html', 
                           redirects=redirects, 
                           trapped_count=trapped_count, 
                           ssh_hits=ssh_hits, 
                           ftp_hits=ftp_hits, 
                           http_hits=http_hits)

# ==========================================
# API ROUTES (For live index.html updates)
# ==========================================

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        total_attacks = cur.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        unique_attackers = cur.execute("SELECT COUNT(DISTINCT ip) FROM attacks").fetchone()[0]
        blocked_ips = cur.execute("SELECT COUNT(DISTINCT ip) FROM attacks WHERE action='FIREWALL_BLOCK'").fetchone()[0]
        redirects = cur.execute("SELECT COUNT(*) FROM attacks WHERE action='REDIRECT_HONEYPOT'").fetchone()[0]
        
        most_targeted_port = cur.execute("SELECT target_port FROM attacks GROUP BY target_port ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
        most_targeted_port = most_targeted_port[0] if most_targeted_port else "N/A"

        common_scan = cur.execute("SELECT scan_type FROM attacks GROUP BY scan_type ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
        common_scan = common_scan[0] if common_scan else "N/A"

        recent_events_query = cur.execute("SELECT timestamp, ip, target_port, scan_type, risk_level, action FROM attacks ORDER BY timestamp DESC LIMIT 10").fetchall()
        recent_events = [dict(row) for row in recent_events_query]
        
    except sqlite3.OperationalError:
        # Failsafe if the database hasn't been initialized by the C engine yet
        total_attacks, unique_attackers, blocked_ips, redirects = 0, 0, 0, 0
        most_targeted_port, common_scan = "N/A", "N/A"
        recent_events = []
        
    conn.close()

    return jsonify({
        "total_attacks": total_attacks,
        "unique_attackers": unique_attackers,
        "blocked_ips": blocked_ips,
        "redirects": redirects,
        "most_targeted_port": most_targeted_port,
        "common_scan": common_scan,
        "recent_events": recent_events
    })

if __name__ == '__main__':
    # Run the dashboard on all interfaces at port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)