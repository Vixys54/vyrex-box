from flask import Flask, render_template_string, request, url_for, send_file, jsonify, abort
import os
import shutil
from werkzeug.utils import secure_filename
import psutil
from datetime import datetime
import mimetypes
from base64 import b64encode

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max por arquivo

# --- CONFIGURAÇÃO E FUNÇÕES AUXILIARES ---

# Pasta DADOS no mesmo diretório do script
DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'DADOS')
os.makedirs(DATA_FOLDER, exist_ok=True)

def get_drives():
    """Retorna uma lista de caminhos de drives disponíveis no sistema."""
    drives = []
    for partition in psutil.disk_partitions():
        if 'cdrom' not in partition.opts.lower() and partition.mountpoint:
            try:
                # Verifica se o drive é acessível antes de adicionar à lista
                psutil.disk_usage(partition.mountpoint)
                drives.append(partition.mountpoint)
            except Exception:
                # Ignora drives que não são acessíveis (ex: leitores de disco vazios)
                pass
    return drives

def safe_path(base, path):
    """
    Valida e retorna um caminho de arquivo seguro, prevenindo ataques de Path Traversal.
    """
    base = os.path.realpath(os.path.abspath(base))
    # Normaliza o caminho relativo, removendo barras extras e caracteres inválidos
    path = path.strip('/').strip('\\').replace('/', os.sep).replace('\\', os.sep)
    
    if not path:
        return base
    
    # Junta o caminho base com o caminho relativo de forma segura
    full_path = os.path.normpath(os.path.join(base, path))
    full_path = os.path.realpath(os.path.abspath(full_path))
    
    # Verifica se o caminho final ainda está dentro do caminho base permitido
    if not full_path.startswith(base):
        print(f"SECURITY: Path traversal blocked! base={base}, requested={path}, full={full_path}")
        abort(403)
    return full_path

# --- CONSTANTES E FUNÇÕES DE UTILIDADE ---

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov', 'mkv', 'zip', 'rar', 'doc', 'docx', 'xls', 'xlsx', 'mp3', 'wav', 'webp', 'bmp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_icon(filename, is_dir):
    if is_dir:
        return '📁'
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    icons = {
        'pdf': '📄', 'txt': '📝', 'doc': '📝', 'docx': '📝',
        'xls': '📊', 'xlsx': '📊',
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'webp': '🖼️', 'bmp': '🖼️',
        'mp4': '🎥', 'avi': '🎥', 'mov': '🎥', 'mkv': '🎥',
        'mp3': '🎵', 'wav': '🎵',
        'zip': '📦', 'rar': '📦'
    }
    return icons.get(ext, '📄')

def format_size(bytes_size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} TB"

def is_image(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return ext in {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'}

def is_video(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return ext in {'mp4', 'avi', 'mov', 'mkv'}

# --- TEMPLATE HTML ---

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gerenciamento Local - {{ current_path if current_path else 'Raiz' }}</title>
    <style>
        :root {
            --bg-color: #1a1a1a;
            --text-color: #ffffff;
            --secondary-text: #a0a0a0;
            --accent-color: #0061ff;
            --card-bg: #2a2a2a;
            --border-color: #404040;
            --hover-bg: #3a3a3a;
        }
        
        body.light {
            --bg-color: #f0f4f8;
            --text-color: #1e293b;
            --secondary-text: #64748b;
            --accent-color: #0061ff;
            --card-bg: #ffffff;
            --border-color: #e2e8f0;
            --hover-bg: #f8fafc;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--card-bg);
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #0061ff 0%, #004aad 100%);
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .header h1 {
            font-size: 24px;
            font-weight: 600;
        }
        
        .header-controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .storage-card {
            background: rgba(255,255,255,0.15);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 15px;
            min-width: 250px;
        }
        
        .storage-title {
            font-size: 13px;
            opacity: 0.9;
            margin-bottom: 8px;
        }
        
        .storage-bar {
            background: rgba(255,255,255,0.2);
            border-radius: 8px;
            height: 10px;
            overflow: hidden;
            margin-bottom: 8px;
        }
        
        .storage-fill {
            background: linear-gradient(90deg, #4ade80 0%, #22c55e 100%);
            height: 100%;
            transition: width 0.3s ease;
            border-radius: 8px;
        }
        
        .storage-fill.warning { background: linear-gradient(90deg, #fbbf24 0%, #f59e0b 100%); }
        .storage-fill.danger { background: linear-gradient(90deg, #f87171 0%, #ef4444 100%); }
        
        .storage-info {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            opacity: 0.9;
        }
        
        .breadcrumb {
            padding: 15px 20px;
            background: var(--hover-bg);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .breadcrumb a, .breadcrumb button {
            color: var(--accent-color);
            text-decoration: none;
            padding: 6px 12px;
            border-radius: 6px;
            transition: background 0.2s;
            background: transparent;
            border: 1px solid var(--border-color);
            cursor: pointer;
            font-size: 14px;
        }
        
        .breadcrumb a:hover, .breadcrumb button:hover {
            background: var(--border-color);
        }
        
        .breadcrumb span {
            color: var(--secondary-text);
        }
        
        .toolbar {
            padding: 15px 20px;
            background: var(--card-bg);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        
        .btn-primary {
            background: var(--accent-color);
            color: white;
        }
        
        .btn-primary:hover {
            background: #0052d9;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0,97,255,0.3);
        }
        
        .btn-secondary {
            background: var(--hover-bg);
            color: var(--text-color);
            border: 1px solid var(--border-color);
        }
        
        .btn-secondary:hover {
            background: var(--border-color);
        }
        
        .btn-danger {
            background: #ef4444;
            color: white;
        }
        
        .btn-danger:hover {
            background: #dc2626;
        }
        
        input[type="text"], input[type="file"], select {
            padding: 8px 12px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            font-size: 13px;
            transition: border 0.2s;
            background: var(--card-bg);
            color: var(--text-color);
        }
        
        input[type="text"]:focus, select:focus {
            outline: none;
            border-color: var(--accent-color);
        }
        
        select {
            cursor: pointer;
        }
        
        .drop-zone {
            margin: 15px 20px;
            padding: 30px;
            border: 3px dashed var(--border-color);
            border-radius: 12px;
            text-align: center;
            background: var(--hover-bg);
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .drop-zone.dragover {
            border-color: var(--accent-color);
            background: var(--border-color);
            transform: scale(1.02);
        }
        
        .drop-zone-text {
            color: var(--secondary-text);
            font-size: 14px;
            margin-top: 8px;
        }
        
        .upload-progress {
            display: none;
            margin: 15px 20px;
            padding: 15px;
            background: var(--hover-bg);
            border-radius: 12px;
        }
        
        .progress-bar-container {
            background: var(--border-color);
            border-radius: 8px;
            height: 6px;
            overflow: hidden;
            margin: 8px 0;
        }
        
        .progress-bar {
            background: linear-gradient(90deg, var(--accent-color) 0%, #004aad 100%);
            height: 100%;
            width: 0%;
            transition: width 0.3s;
        }
        
        .progress-info {
            display: flex;
            justify-content: space-between;
            color: var(--secondary-text);
            font-size: 12px;
            margin-top: 6px;
        }
        
        .file-list {
            padding: 0 20px 20px;
        }
        
        .file-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .file-table th {
            text-align: left;
            padding: 10px;
            background: var(--hover-bg);
            color: var(--text-color);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .file-table td {
            padding: 12px 10px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .file-table tr:hover {
            background: var(--hover-bg);
        }
        
        .file-name {
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--text-color);
            text-decoration: none;
            font-weight: 500;
            cursor: pointer;
        }
        
        .file-name:hover {
            color: var(--accent-color);
        }
        
        .file-icon {
            font-size: 20px;
        }
        
        .file-actions {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }
        
        .action-btn {
            padding: 4px 10px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--card-bg);
            color: var(--secondary-text);
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-block;
        }
        
        .action-btn:hover {
            border-color: var(--accent-color);
            color: var(--accent-color);
        }
        
        .checkbox {
            width: 16px;
            height: 16px;
            cursor: pointer;
        }
        
        .empty-state {
            text-align: center;
            padding: 50px 15px;
            color: var(--secondary-text);
        }
        
        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 12px;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 25px;
            max-width: 500px;
            width: 100%;
            color: var(--text-color);
            max-height: 90vh;
            overflow: auto;
        }
        
        .modal-header {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 15px;
        }
        
        .preview-modal .modal-content {
            max-width: 90%;
        }
        
        .preview-content {
            max-width: 100%;
            max-height: 70vh;
            object-fit: contain;
        }
        
        @media (max-width: 768px) {
            .header { flex-direction: column; }
            .header-controls { flex-direction: column; width: 100%; }
            .storage-card { width: 100%; }
            .toolbar { flex-direction: column; }
            .file-table { font-size: 12px; }
            .file-table th, .file-table td { padding: 8px 4px; }
        }
    </style>
</head>
<body class="dark">
    <div class="container">
        <div class="header">
            <h1>📦 Vyrex Local</h1>
            <div class="header-controls">
                <select id="drive-select" onchange="changeDrive(this.value)">
                    {% for drive in drives %}
                        <option value="{{ drive }}" {% if current_drive_for_url == drive %}selected{% endif %}>💾 {{ drive }}</option>
                    {% endfor %}
                    <option value="DADOS" {% if current_drive_for_url == 'DADOS' %}selected{% endif %}>📁 DADOS (Local)</option>
                </select>
                <button class="btn btn-secondary" onclick="toggleTheme()">🌙/☀️</button>
            </div>
            <div class="storage-card">
                <div class="storage-title">💾 {{ current_drive_for_url }}</div>
                <div class="storage-bar">
                    <div class="storage-fill {% if usage_percent > 90 %}danger{% elif usage_percent > 70 %}warning{% endif %}" 
                         style="width: {{ usage_percent }}%"></div>
                </div>
                <div class="storage-info">
                    <span>{{ "%.2f"|format(used_gb) }} GB</span>
                    <span>{{ "%.2f"|format(free_gb) }} GB livre</span>
                </div>
            </div>
        </div>
        
        <div class="breadcrumb">
            <a href="{{ url_for('index', drive=current_drive_for_url) }}">🏠 Raiz</a>
            {% if current_path %}
                {% set parts = current_path.split('/') %}
                {% for i in range(parts|length) %}
                    {% if parts[i] %}
                        <span>›</span>
                        {% set path = '/'.join(parts[:i+1]) %}
                        <a href="{{ url_for('index', drive=current_drive_for_url, path=path) }}">{{ parts[i] }}</a>
                    {% endif %}
                {% endfor %}
            {% endif %}
        </div>
        
        <div class="toolbar">
            <button class="btn btn-primary" onclick="document.getElementById('file-input').click()">
                📤 Upload
            </button>
            <input type="file" id="file-input" multiple style="display: none;">
            
            <button class="btn btn-secondary" onclick="showCreateFolder()">
                📁 Nova Pasta
            </button>
            
            <button class="btn btn-secondary" onclick="downloadSelected()">
                ⬇️ Baixar
            </button>
            
            <button class="btn btn-danger" onclick="deleteSelected()">
                🗑️ Apagar
            </button>
            
            <button class="btn btn-secondary" onclick="showMoveModal()">
                📋 Mover
            </button>
        </div>
        
        <div class="drop-zone" id="drop-zone">
            <div style="font-size: 40px;">📤</div>
            <div class="drop-zone-text">Arraste arquivos aqui ou clique em Upload</div>
        </div>
        
        <div class="upload-progress" id="upload-progress">
            <div style="font-weight: 600; margin-bottom: 8px;">Enviando...</div>
            <div class="progress-bar-container">
                <div class="progress-bar" id="progress-bar"></div>
            </div>
            <div class="progress-info">
                <span id="progress-percent">0%</span>
                <span id="progress-speed">0 KB/s</span>
            </div>
        </div>
        
        <div class="file-list">
            {% if items %}
            <table class="file-table">
                <thead>
                    <tr>
                        <th style="width: 40px;">
                            <input type="checkbox" class="checkbox" id="select-all">
                        </th>
                        <th>Nome</th>
                        <th style="width: 100px;">Tamanho</th>
                        <th style="width: 140px;">Modificado</th>
                        <th style="width: 180px;">Ações</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in items %}
                    <tr>
                        <td>
                            <input type="checkbox" class="checkbox item-checkbox" value="{{ item.path }}">
                        </td>
                        <td>
                            {% if item.is_dir %}
                                <a href="{{ url_for('index', drive=current_drive_for_url, path=item.path) }}" class="file-name">
                                    <span class="file-icon">{{ item.icon }}</span>
                                    <span>{{ item.name }}</span>
                                </a>
                            {% else %}
                                <div class="file-name" onclick="previewFile('{{ item.path }}', {{ item.is_image|lower }}, {{ item.is_video|lower }})">
                                    <span class="file-icon">{{ item.icon }}</span>
                                    <span>{{ item.name }}</span>
                                </div>
                            {% endif %}
                        </td>
                        <td>{{ item.size_str }}</td>
                        <td>{{ item.mtime }}</td>
                        <td>
                            <div class="file-actions">
                                <button class="action-btn" onclick="renameItem('{{ item.path }}', '{{ item.name }}')">
                                    ✏️
                                </button>
                                {% if not item.is_dir %}
                                    <a href="{{ url_for('download_file', filename=item.path, drive=current_drive_for_url) }}" class="action-btn" download>
                                        ⬇️
                                    </a>
                                {% endif %}
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">
                <div class="empty-state-icon">📭</div>
                <div style="font-size: 16px; margin-bottom: 8px;">Pasta vazia</div>
                <div>Faça upload de arquivos ou crie pastas</div>
            </div>
            {% endif %}
        </div>
    </div>
    
    <!-- Modal Nova Pasta -->
    <div class="modal" id="folder-modal">
        <div class="modal-content">
            <div class="modal-header">📁 Nova Pasta</div>
            <form id="folder-form" onsubmit="createFolder(event)">
                <input type="text" id="folder-name" placeholder="Nome da pasta" style="width: 100%; margin-bottom: 20px;" required>
                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('folder-modal')">Cancelar</button>
                    <button type="submit" class="btn btn-primary">Criar</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Modal Mover -->
    <div class="modal" id="move-modal">
        <div class="modal-content">
            <div class="modal-header">📋 Mover Itens</div>
            <form id="move-form" onsubmit="moveItems(event)">
                <input type="text" id="target-folder" placeholder="Pasta destino (ex: docs/2024)" style="width: 100%; margin-bottom: 20px;" required>
                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('move-modal')">Cancelar</button>
                    <button type="submit" class="btn btn-primary">Mover</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Modal Preview -->
    <div class="modal preview-modal" id="preview-modal">
        <div class="modal-content">
            <div class="modal-header">Visualização</div>
            <div id="preview-container"></div>
            <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
                <button type="button" class="btn btn-secondary" onclick="closeModal('preview-modal')">Fechar</button>
            </div>
        </div>
    </div>
    
    <script>
        const currentPath = '{{ current_path }}';
        const currentDrive = '{{ current_drive_for_url }}';
        
        // Tema
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.body.className = savedTheme;
        
        function toggleTheme() {
            const newTheme = document.body.className === 'dark' ? 'light' : 'dark';
            document.body.className = newTheme;
            localStorage.setItem('theme', newTheme);
        }
        
        function changeDrive(drive) {
            window.location.href = '/?drive=' + encodeURIComponent(drive);
        }
        
        // Select All
        document.getElementById('select-all').addEventListener('change', function() {
            document.querySelectorAll('.item-checkbox').forEach(cb => cb.checked = this.checked);
        });
        
        // Drag and Drop
        const dropZone = document.getElementById('drop-zone');
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, e => {
                e.preventDefault();
                e.stopPropagation();
            });
        });
        
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'));
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'));
        });
        
        dropZone.addEventListener('drop', e => uploadFiles(e.dataTransfer.files));
        dropZone.addEventListener('click', () => document.getElementById('file-input').click());
        
        document.getElementById('file-input').addEventListener('change', function() {
            uploadFiles(this.files);
        });
        
        // Upload
        function uploadFiles(files) {
            if (!files || files.length === 0) return;
            
            const progressDiv = document.getElementById('upload-progress');
            const progressBar = document.getElementById('progress-bar');
            const progressPercent = document.getElementById('progress-percent');
            const progressSpeed = document.getElementById('progress-speed');
            
            progressDiv.style.display = 'block';
            
            const formData = new FormData();
            formData.append('path', currentPath);
            formData.append('drive', currentDrive);
            Array.from(files).forEach(file => formData.append('files[]', file));
            
            const startTime = Date.now();
            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', e => {
                if (e.lengthComputable) {
                    const percent = (e.loaded / e.total) * 100;
                    progressBar.style.width = percent + '%';
                    progressPercent.textContent = Math.round(percent) + '%';
                    
                    const elapsed = (Date.now() - startTime) / 1000;
                    const speed = e.loaded / elapsed;
                    progressSpeed.textContent = formatSize(speed) + '/s';
                }
            });
            
            xhr.addEventListener('load', () => {
                if (xhr.status === 200) {
                    setTimeout(() => location.reload(), 500);
                } else {
                    alert('Erro no upload!');
                    progressDiv.style.display = 'none';
                }
            });
            
            xhr.addEventListener('error', () => {
                alert('Erro na conexão!');
                progressDiv.style.display = 'none';
            });
            
            xhr.open('POST', '/upload');
            xhr.send(formData);
        }
        
        function formatSize(bytes) {
            const units = ['B', 'KB', 'MB', 'GB'];
            let i = 0;
            while (bytes >= 1024 && i < units.length - 1) {
                bytes /= 1024;
                i++;
            }
            return bytes.toFixed(2) + ' ' + units[i];
        }
        
        // Preview
        function previewFile(path, isImage, isVideo) {
            if (!isImage && !isVideo) return;
            
            const container = document.getElementById('preview-container');
            container.innerHTML = '<p>Carregando...</p>';
            
            fetch('/preview?filename=' + encodeURIComponent(path) + '&drive=' + encodeURIComponent(currentDrive))
                .then(response => response.json())
                .then(data => {
                    if (isImage) {
                        container.innerHTML = `<img src="data:${data.mime};base64,${data.base64}" class="preview-content" alt="Preview">`;
                    } else if (isVideo) {
                        container.innerHTML = `<video controls class="preview-content">
                            <source src="data:${data.mime};base64,${data.base64}" type="${data.mime}">
                        </video>`;
                    }
                    document.getElementById('preview-modal').classList.add('active');
                })
                .catch(error => {
                    alert('Erro ao carregar: ' + error);
                    container.innerHTML = '';
                });
        }
        
        // Modais
        function showCreateFolder() {
            document.getElementById('folder-modal').classList.add('active');
            document.getElementById('folder-name').focus();
        }
        
        function showMoveModal() {
            const selected = getSelectedItems();
            if (selected.length === 0) {
                alert('Selecione itens para mover');
                return;
            }
            document.getElementById('move-modal').classList.add('active');
            document.getElementById('target-folder').focus();
        }
        
        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }
        
        // Criar pasta
        function createFolder(e) {
            e.preventDefault();
            const folderName = document.getElementById('folder-name').value.trim();
            if (!folderName) return;
            
            fetch('/create_folder', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    path: currentPath,
                    folder_name: folderName,
                    drive: currentDrive
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Erro: ' + (data.error || 'Desconhecido'));
                }
            })
            .catch(error => alert('Erro ao criar pasta: ' + error));
        }
        
        // Mover itens
        function moveItems(e) {
            e.preventDefault();
            const targetFolder = document.getElementById('target-folder').value.trim();
            const selected = getSelectedItems();
            
            if (!targetFolder || selected.length === 0) return;
            
            fetch('/move', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    path: currentPath,
                    target_path: targetFolder,
                    selected: selected,
                    drive: currentDrive
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Erro: ' + (data.error || 'Desconhecido'));
                }
            })
            .catch(error => alert('Erro ao mover: ' + error));
        }
        
        // Renomear
        function renameItem(path, oldName) {
            const newName = prompt('Novo nome:', oldName);
            if (!newName || newName === oldName) return;
            
            fetch('/rename', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    old_path: path,
                    new_name: newName,
                    drive: currentDrive
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Erro: ' + (data.error || 'Desconhecido'));
                }
            })
            .catch(error => alert('Erro ao renomear: ' + error));
        }
        
        // Download múltiplo
        function downloadSelected() {
            const selected = getSelectedItems();
            if (selected.length === 0) {
                alert('Selecione itens para baixar');
                return;
            }
            selected.forEach(path => {
                const url = '/download?filename=' + encodeURIComponent(path) + '&drive=' + encodeURIComponent(currentDrive);
                window.open(url, '_blank');
            });
        }
        
        // Apagar
        function deleteSelected() {
            const selected = getSelectedItems();
            if (selected.length === 0) {
                alert('Selecione itens para apagar');
                return;
            }
            if (!confirm(`Apagar ${selected.length} item(ns)?`)) return;
            
            fetch('/delete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    path: currentPath,
                    selected: selected,
                    drive: currentDrive
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Erro: ' + (data.error || 'Desconhecido'));
                }
            })
            .catch(error => alert('Erro ao apagar: ' + error));
        }
        
        function getSelectedItems() {
            return Array.from(document.querySelectorAll('.item-checkbox:checked')).map(cb => cb.value);
        }
        
        // Fechar modal ao clicar fora
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', function(e) {
                if (e.target === this) {
                    this.classList.remove('active');
                }
            });
        });
    </script>
</body>
</html>
'''

# --- ROTAS DA APLICAÇÃO WEB ---

@app.route('/')
def index():
    raw_drive = request.args.get('drive', 'DADOS')
    
    # Se o drive for o identificador 'DADOS', usa o caminho completo da pasta DADOS
    if raw_drive == 'DADOS':
        current_drive = DATA_FOLDER
    # Se for um drive de disco (ex: 'C:'), normaliza para 'C:\'
    elif len(raw_drive) == 2 and raw_drive[1] == ':':
        current_drive = raw_drive + os.sep
    # Caso contrário, usa o valor recebido (não deveria acontecer, mas é seguro)
    else:
        current_drive = raw_drive

    # Valida se o drive normalizado existe ou se é a pasta DADOS
    all_possible_drives = get_drives()
    if current_drive not in all_possible_drives and current_drive != DATA_FOLDER:
        current_drive = DATA_FOLDER
        raw_drive = 'DADOS'

    current_path = request.args.get('path', '').strip('/').strip('\\')
    
    try:
        full_path = safe_path(current_drive, current_path)
        
        items = []
        for item in os.listdir(full_path):
            try:
                item_path = os.path.join(full_path, item)
                is_dir = os.path.isdir(item_path)
                size = os.path.getsize(item_path) if not is_dir else 0
                mtime = datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%d/%m/%Y %H:%M')
                
                # O caminho relativo para a URL deve sempre usar '/'
                rel_item_path = f"{current_path}/{item}".replace('\\', '/') if current_path else item
                
                items.append({
                    'name': item,
                    'path': rel_item_path,
                    'is_dir': is_dir,
                    'size': size,
                    'size_str': '-' if is_dir else format_size(size),
                    'mtime': mtime,
                    'icon': get_file_icon(item, is_dir),
                    'is_image': is_image(item),
                    'is_video': is_video(item)
                })
            except Exception as e:
                print(f"Erro ao processar {item}: {e}")
                continue
        
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        
    except PermissionError:
        return "Sem permissão para acessar esta pasta", 403
    except Exception as e:
        print(f"Erro ao listar: {e}")
        import traceback
        traceback.print_exc()
        return f"Erro ao listar arquivos: {e}", 500
    
    # Info do disco
    try:
        disk = psutil.disk_usage(current_drive)
        total_gb = disk.total / (1024**3)
        used_gb = disk.used / (1024**3)
        free_gb = disk.free / (1024**3)
        usage_percent = (used_gb / total_gb) * 100
    except Exception:
        total_gb = used_gb = free_gb = usage_percent = 0
    
    # Prepara as variáveis para o template
    template_drives = [d.rstrip(os.sep) for d in get_drives()]
    current_drive_for_url = raw_drive # Usa o identificador 'DADOS' ou 'C:'
    
    return render_template_string(
        HTML_TEMPLATE,
        items=items,
        current_path=current_path,
        current_drive=current_drive,           # Caminho completo (C:\) para lógica do JS
        current_drive_for_url=current_drive_for_url, # Drive limpo (C:) para as URLs
        drives=template_drives,                # Lista limpa (C:, D:) para o dropdown
        data_folder=DATA_FOLDER,
        total_gb=total_gb,
        used_gb=used_gb,
        free_gb=free_gb,
        usage_percent=usage_percent
    )

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        raw_drive = request.form.get('drive', 'DADOS')
        if raw_drive == 'DADOS':
            current_drive = DATA_FOLDER
        elif len(raw_drive) == 2 and raw_drive[1] == ':':
            current_drive = raw_drive + os.sep
        else:
            current_drive = raw_drive

        current_path = request.form.get('path', '').strip('/').strip('\\')
        
        full_path = safe_path(current_drive, current_path)
        
        if 'files[]' not in request.files:
            return jsonify({'error': 'Nenhum arquivo selecionado'}), 400
        
        files = request.files.getlist('files[]')
        saved_count = 0
        
        for file in files:
            if file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                target_path = os.path.join(full_path, filename)
                file.save(target_path)
                saved_count += 1
        
        if saved_count == 0:
            return jsonify({'error': 'Nenhum arquivo válido para upload'}), 400
        
        return jsonify({'success': True, 'saved': saved_count})
    
    except Exception as e:
        print(f"Erro no upload: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/create_folder', methods=['POST'])
def create_folder():
    try:
        data = request.get_json()
        
        raw_drive = data.get('drive', 'DADOS')
        if raw_drive == 'DADOS':
            current_drive = DATA_FOLDER
        elif len(raw_drive) == 2 and raw_drive[1] == ':':
            current_drive = raw_drive + os.sep
        else:
            current_drive = raw_drive

        current_path = data.get('path', '').strip('/').strip('\\')
        folder_name = secure_filename(data.get('folder_name', '').strip())

        if not folder_name:
            return jsonify({'error': 'Nome de pasta inválido'}), 400

        full_current_path = safe_path(current_drive, current_path)
        new_folder_path = os.path.join(full_current_path, folder_name)

        os.makedirs(new_folder_path, exist_ok=True)
        print(f"Pasta criada com sucesso: {new_folder_path}")

        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Erro ao criar pasta: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/rename', methods=['POST'])
def rename():
    try:
        data = request.get_json()
        
        raw_drive = data.get('drive', 'DADOS')
        if raw_drive == 'DADOS':
            current_drive = DATA_FOLDER
        elif len(raw_drive) == 2 and raw_drive[1] == ':':
            current_drive = raw_drive + os.sep
        else:
            current_drive = raw_drive
            
        old_path = data.get('old_path', '').strip('/').strip('\\')
        new_name = secure_filename(data.get('new_name', '').strip())

        if not new_name:
            return jsonify({'error': 'Nome inválido'}), 400

        full_old_path = safe_path(current_drive, old_path)
        
        if not os.path.exists(full_old_path):
            return jsonify({'error': 'Arquivo ou pasta não encontrado'}), 404

        parent_directory = os.path.dirname(full_old_path)
        full_new_path = os.path.join(parent_directory, new_name)
        
        if os.path.exists(full_new_path):
            return jsonify({'error': 'Já existe um item com este nome'}), 400

        shutil.move(full_old_path, full_new_path)
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Erro ao renomear: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/delete', methods=['POST'])
def delete():
    try:
        data = request.get_json()
        
        raw_drive = data.get('drive', 'DADOS')
        if raw_drive == 'DADOS':
            current_drive = DATA_FOLDER
        elif len(raw_drive) == 2 and raw_drive[1] == ':':
            current_drive = raw_drive + os.sep
        else:
            current_drive = raw_drive
            
        paths = data.get('selected', [])
        
        deleted = 0
        for path in paths:
            path = path.strip('/').strip('\\')
            full_path = safe_path(current_drive, path)
            
            if os.path.exists(full_path):
                if os.path.isdir(full_path):
                    shutil.rmtree(full_path)
                else:
                    os.remove(full_path)
                deleted += 1
        
        return jsonify({'success': True, 'deleted': deleted})
    
    except Exception as e:
        print(f"Erro ao apagar: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/move', methods=['POST'])
def move():
    try:
        data = request.get_json()
        
        raw_drive = data.get('drive', 'DADOS')
        if raw_drive == 'DADOS':
            current_drive = DATA_FOLDER
        elif len(raw_drive) == 2 and raw_drive[1] == ':':
            current_drive = raw_drive + os.sep
        else:
            current_drive = raw_drive
            
        target_rel = data.get('target_path', '').strip('/').strip('\\')
        paths = data.get('selected', [])
        
        if not target_rel:
            return jsonify({'error': 'Destino inválido'}), 400
        
        target_full = safe_path(current_drive, target_rel)
        
        if not os.path.exists(target_full):
            os.makedirs(target_full, exist_ok=True)
        
        moved = 0
        for path in paths:
            path = path.strip('/').strip('\\')
            full_old = safe_path(current_drive, path)
            
            if not os.path.exists(full_old):
                continue
            
            basename = os.path.basename(full_old)
            full_new = os.path.join(target_full, basename)
            
            if full_old != full_new and not os.path.exists(full_new):
                shutil.move(full_old, full_new)
                moved += 1
        
        return jsonify({'success': True, 'moved': moved})
    
    except Exception as e:
        print(f"Erro ao mover: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/download')
def download_file():
    try:
        raw_drive = request.args.get('drive', 'DADOS')
        if raw_drive == 'DADOS':
            current_drive = DATA_FOLDER
        elif len(raw_drive) == 2 and raw_drive[1] == ':':
            current_drive = raw_drive + os.sep
        else:
            current_drive = raw_drive

        filename = request.args.get('filename', '').strip('/').strip('\\')
        full_path = safe_path(current_drive, filename)
        
        if os.path.exists(full_path) and not os.path.isdir(full_path):
            return send_file(full_path, as_attachment=True)
        
        return "Arquivo não encontrado", 404
    
    except Exception as e:
        print(f"Erro no download: {e}")
        return str(e), 500

@app.route('/preview')
def preview_file():
    try:
        raw_drive = request.args.get('drive', 'DADOS')
        if raw_drive == 'DADOS':
            current_drive = DATA_FOLDER
        elif len(raw_drive) == 2 and raw_drive[1] == ':':
            current_drive = raw_drive + os.sep
        else:
            current_drive = raw_drive
            
        filename = request.args.get('filename', '').strip('/').strip('\\')
        full_path = safe_path(current_drive, filename)
        
        if not os.path.exists(full_path) or os.path.isdir(full_path):
            return jsonify({'error': 'Arquivo não encontrado'}), 404
        
        if os.path.getsize(full_path) > 50 * 1024 * 1024:
            return jsonify({'error': 'Arquivo muito grande para preview'}), 400
        
        with open(full_path, 'rb') as f:
            data = f.read()
        
        mime = mimetypes.guess_type(full_path)[0] or 'application/octet-stream'
        base64_data = b64encode(data).decode('utf-8')
        
        return jsonify({'base64': base64_data, 'mime': mime})
    
    except Exception as e:
        print(f"Erro no preview: {e}")
        return jsonify({'error': str(e)}), 500

# --- INICIALIZAÇÃO DO SERVIDOR ---

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 VYREX-BOX LOCAL INICIADO COM SUCESSO!")
    print("="*60)
    print(f"📁 Pasta DADOS: {DATA_FOLDER}")
    print(f"🌐 Acesse: http://localhost:5000")
    print(f"📱 No celular (mesma rede): http://SEU_IP_LOCAL:5000")
    print("\n💡 Dica: Use 'ipconfig' (Windows) ou 'ifconfig' (Linux/Mac)")
    print("   para descobrir seu IP local")
    print("="*60 + "\n")
    # Em produção, use um servidor WSGI como Gunicorn ou uWSGI e desative o debug
    app.run(debug=True, host='0.0.0.0', port=5000)