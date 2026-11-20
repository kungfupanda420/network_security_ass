from flask import Flask, render_template, jsonify
import sqlite3
import os
from collections import defaultdict, Counter

app = Flask(__name__)

# Path to SQLite database
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'alerts.db')


def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if not os.path.exists(DB_PATH):
        open(DB_PATH, 'a').close()

    # timeout=5.0 avoids "database is locked" while the C engine writes concurrently
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


# ==========================================
# PAGE ROUTES
# ==========================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/events')
def events():
    conn = get_db_connection()
    try:
        events = conn.execute(
            "SELECT * FROM attacks ORDER BY timestamp DESC"
        ).fetchall()
    except sqlite3.OperationalError:
        events = []
    conn.close()
    return render_template('events.html', events=events)


@app.route('/attackers')
def attackers():
    conn = get_db_connection()
    try:
        raw_data = conn.execute(
            "SELECT ip, target_port, risk_level FROM attacks"
        ).fetchall()
    except sqlite3.OperationalError:
        raw_data = []
    conn.close()

    ips_data = defaultdict(lambda: {'count': 0, 'ports': Counter(), 'risks': set()})

    for row in raw_data:
        ip = row['ip']
        ips_data[ip]['count'] += 1
        ips_data[ip]['ports'][row['target_port']] += 1
        ips_data[ip]['risks'].add(row['risk_level'])

    attackers_list = []
    for ip, data in ips_data.items():
        top_port = data['ports'].most_common(1)[0][0]

        if 'HIGH' in data['risks']:
            max_risk = 'HIGH'
        elif 'MEDIUM' in data['risks']:
            max_risk = 'MEDIUM'
        elif 'LOW' in data['risks']:
            max_risk = 'LOW'
        else:
            max_risk = 'UNKNOWN'

        attackers_list.append({
            'ip': ip,
            'packet_count': data['count'],
            'top_port': top_port,
            'max_risk': max_risk
        })

    attackers_list = sorted(attackers_list, key=lambda x: x['packet_count'], reverse=True)
    return render_template('attackers.html', attackers=attackers_list)


@app.route('/honeypot')
def honeypot():
    conn = get_db_connection()
    try:
        redirects = conn.execute(
            """
            SELECT * FROM attacks
            WHERE action IN ('REDIRECT_HONEYPOT', 'SSH_HONEYPOT_TRAP', 'HTTP_HONEYPOT_TRAP', 'FTP_HONEYPOT_TRAP')
            ORDER BY timestamp DESC
            """
        ).fetchall()
    except sqlite3.OperationalError:
        redirects = []

    try:
        honeypot_logs = conn.execute(
            "SELECT * FROM honeypot_logs ORDER BY id DESC LIMIT 200"
        ).fetchall()
    except sqlite3.OperationalError:
        honeypot_logs = []

    try:
        keystrokes = conn.execute(
            "SELECT * FROM ssh_keystrokes ORDER BY id DESC LIMIT 300"
        ).fetchall()
    except sqlite3.OperationalError:
        keystrokes = []

    conn.close()

    trapped_count = len(redirects)
    ssh_hits = sum(1 for r in redirects if r['target_port'] == 22 or r['action'] == 'SSH_HONEYPOT_TRAP')
    ftp_hits = sum(1 for r in redirects if r['target_port'] == 21 or r['action'] == 'FTP_HONEYPOT_TRAP')
    http_hits = trapped_count - ssh_hits - ftp_hits

    return render_template(
        'honeypot.html',
        redirects=redirects,
        trapped_count=trapped_count,
        ssh_hits=ssh_hits,
        ftp_hits=ftp_hits,
        http_hits=http_hits,
        honeypot_logs=honeypot_logs,
        keystrokes=keystrokes
    )


# ==========================================
# API ROUTES
# ==========================================

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        total_attacks = cur.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        unique_attackers = cur.execute("SELECT COUNT(DISTINCT ip) FROM attacks").fetchone()[0]
        blocked_ips = cur.execute(
            "SELECT COUNT(DISTINCT ip) FROM attacks WHERE action='FIREWALL_BLOCK'"
        ).fetchone()[0]
        redirects = cur.execute(
            """
            SELECT COUNT(*) FROM attacks
            WHERE action IN ('REDIRECT_HONEYPOT', 'SSH_HONEYPOT_TRAP', 'HTTP_HONEYPOT_TRAP', 'FTP_HONEYPOT_TRAP')
            """
        ).fetchone()[0]

        most_targeted_port = cur.execute(
            "SELECT target_port FROM attacks GROUP BY target_port ORDER BY COUNT(*) DESC LIMIT 1"
        ).fetchone()
        most_targeted_port = most_targeted_port[0] if most_targeted_port else "N/A"

        common_scan = cur.execute(
            "SELECT scan_type FROM attacks GROUP BY scan_type ORDER BY COUNT(*) DESC LIMIT 1"
        ).fetchone()
        common_scan = common_scan[0] if common_scan else "N/A"

        recent_events_query = cur.execute(
            "SELECT timestamp, ip, target_port, scan_type, risk_level, action FROM attacks ORDER BY timestamp DESC LIMIT 10"
        ).fetchall()
        recent_events = [dict(row) for row in recent_events_query]

    except sqlite3.OperationalError:
        total_attacks, unique_attackers, blocked_ips, redirects = 0, 0, 0, 0
        most_targeted_port, common_scan = "N/A", "N/A"
        recent_events = []

    try:
        total_keystrokes = conn.execute("SELECT COUNT(*) FROM ssh_keystrokes").fetchone()[0]
    except sqlite3.OperationalError:
        total_keystrokes = 0

    try:
        total_honeypot_logs = conn.execute("SELECT COUNT(*) FROM honeypot_logs").fetchone()[0]
    except sqlite3.OperationalError:
        total_honeypot_logs = 0

    conn.close()

    return jsonify({
        "total_attacks": total_attacks,
        "unique_attackers": unique_attackers,
        "blocked_ips": blocked_ips,
        "redirects": redirects,
        "most_targeted_port": most_targeted_port,
        "common_scan": common_scan,
        "total_honeypot_logs": total_honeypot_logs,
        "total_keystrokes": total_keystrokes,
        "recent_events": recent_events
    })


@app.route('/api/honeypot_logs')
def get_honeypot_logs():
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, timestamp, service, ip, event_type, details FROM honeypot_logs ORDER BY id DESC LIMIT 200"
        ).fetchall()
        data = [dict(r) for r in rows]
    except sqlite3.OperationalError:
        data = []
    conn.close()
    return jsonify(data)


@app.route('/api/keystrokes')
def get_keystrokes():
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, timestamp, ip, username, keystroke FROM ssh_keystrokes ORDER BY id DESC LIMIT 500"
        ).fetchall()
        data = [dict(r) for r in rows]
    except sqlite3.OperationalError:
        data = []
    conn.close()
    return jsonify(data)


@app.route('/api/keystrokes/<ip>')
def get_keystrokes_by_ip(ip):
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, timestamp, ip, username, keystroke FROM ssh_keystrokes WHERE ip = ? ORDER BY id ASC",
            (ip,)
        ).fetchall()
        data = [dict(r) for r in rows]
    except sqlite3.OperationalError:
        data = []
    conn.close()
    return jsonify(data)


if __name__ == '__main__':
    # debug=False & use_reloader=False so start_all.sh can cleanly terminate Flask on Ctrl+C
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)