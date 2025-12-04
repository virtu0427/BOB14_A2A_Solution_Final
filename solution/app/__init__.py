import os

from flask import Flask, redirect, request, send_from_directory, url_for

from .core import repo

BASEDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def ensure_files() -> None:
    """Ensure repository seed files exist before serving requests."""
    repo.ensure_seed()


def create_app() -> Flask:
    if os.path.isdir(os.path.join(BASEDIR, 'frontend')):
        static_root = os.path.join(BASEDIR, 'frontend')
    elif os.path.isdir(os.path.join(BASEDIR, 'webui', 'dist')):
        static_root = os.path.join(BASEDIR, 'webui', 'dist')
    else:
        static_root = os.path.join(BASEDIR, 'webui')

    app = Flask(__name__, static_folder=static_root, static_url_path='')
    app.config['JSON_AS_ASCII'] = False

    app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    app.config['USERME_DIRECT_URL'] = os.environ.get('USERME_DIRECT_URL', 'http://127.0.0.1:8000/users/me')

    ensure_files()

    @app.after_request
    def _force_utf8(resp):
        try:
            ctype = resp.headers.get('Content-Type', '')
            if ('charset=' not in ctype) and (
                resp.mimetype and (resp.mimetype.startswith('text/') or resp.mimetype == 'application/json')
            ):
                resp.headers['Content-Type'] = f"{resp.mimetype}; charset=utf-8"
        except Exception:
            pass
        return resp

    @app.get('/')
    def root():
        if os.path.exists(os.path.join(app.static_folder, 'dashboard.html')):
            return send_from_directory(app.static_folder, 'dashboard.html')
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/dashboard')
    def dashboard_page():
        target = os.path.join(app.static_folder, 'dashboard.html')
        if os.path.exists(target):
            return send_from_directory(app.static_folder, 'dashboard.html')
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/agents')
    def agents_page():
        target_idx = os.path.join(app.static_folder, 'agents', 'index.html')
        if os.path.exists(target_idx):
            return send_from_directory(os.path.dirname(target_idx), os.path.basename(target_idx))
        target = os.path.join(app.static_folder, 'agents', 'agents.html')
        if os.path.exists(target):
            return send_from_directory(os.path.dirname(target), os.path.basename(target))
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/logs')
    def logs_page_redirect():
        target = url_for('logs_page')
        if request.query_string:
            target = f"{target}?{request.query_string.decode('utf-8')}"
        return redirect(target)

    @app.get('/logs/')
    def logs_page():
        target = os.path.join(app.static_folder, 'logs', 'logs.html')
        if os.path.exists(target):
            return send_from_directory(os.path.dirname(target), os.path.basename(target))
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/rulesets')
    def ruleset_page_redirect():
        target = url_for('ruleset_page')
        if request.query_string:
            target = f"{target}?{request.query_string.decode('utf-8')}"
        return redirect(target)

    @app.get('/rulesets/')
    def ruleset_page():
        # ?? ?? ?? ?? ?? ??? ??? ??
        candidates = [
            os.path.join(app.static_folder, 'rulesets', 'rulesets.html'),
            os.path.join(app.static_folder, 'ruleset', 'rulesets.html'),
        ]
        for target in candidates:
            if os.path.exists(target):
                return send_from_directory(os.path.dirname(target), os.path.basename(target))
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/ruleset')
    @app.get('/ruleset/')
    @app.get('/rulsets')
    @app.get('/rulsets/')
    def ruleset_redirect():
        return redirect(url_for('ruleset_page'))


    from .api import api_bp

    app.register_blueprint(api_bp)
    return app
