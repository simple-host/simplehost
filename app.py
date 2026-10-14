import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import zipfile
from contextlib import closing
from pathlib import Path, PurePosixPath

from flask import (
    Flask, request, redirect, url_for, render_template_string,
    abort, send_from_directory, flash
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# On Render, set UPLOAD_FOLDER to a mounted persistent disk path if you want
# uploaded sites to survive redeploys/restarts.
UPLOAD_FOLDER = Path(os.environ.get("UPLOAD_FOLDER", "uploads")).resolve()
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB per upload

ALLOWED_UPLOADS = {".html", ".zip"}
MAX_ZIP_FILES = 500
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB total extracted size

# ---------------------------------------------------------------------------
# Per-IP site limit
# ---------------------------------------------------------------------------
MAX_SITES_PER_IP = int(os.environ.get("MAX_SITES_PER_IP", 5))

# Behind Render's proxy, request.remote_addr is the proxy's IP unless we trust
# the forwarded header. Set TRUSTED_PROXIES to the number of proxies in front
# of the app (Render = 1).
TRUSTED_PROXIES = int(os.environ.get("TRUSTED_PROXIES", 1))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES)

# A file (not a folder), so it can never collide with a site slug.
DB_PATH = UPLOAD_FOLDER / "_sites.db"


def get_db() -> sqlite3.Connection:
    # isolation_level=None -> we control transactions manually
    return sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)


def init_db() -> None:
    with closing(get_db()) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS sites (
                   slug TEXT PRIMARY KEY,
                   ip_hash TEXT NOT NULL,
                   created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
               )"""
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_sites_ip ON sites(ip_hash)")
        db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('ip_salt', ?)",
            (secrets.token_hex(16),),
        )


init_db()


def normalize_ip(raw: str | None) -> str:
    """IPv6 users often control a whole /64, so count them by that prefix."""
    try:
        addr = ipaddress.ip_address(raw or "")
    except ValueError:
        return raw or "unknown"
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def client_id() -> str:
    """Salted hash of the client's IP. Raw addresses are never stored."""
    ip = normalize_ip(request.remote_addr)
    with closing(get_db()) as db:
        salt = db.execute("SELECT value FROM meta WHERE key = 'ip_salt'").fetchone()[0]
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()


def reserve_site(ip_hash: str, slug: str) -> bool:
    """Atomically check the quota and claim the slug. False = limit reached."""
    with closing(get_db()) as db:
        db.execute("BEGIN IMMEDIATE")  # serializes concurrent uploads
        try:
            (count,) = db.execute(
                "SELECT COUNT(*) FROM sites WHERE ip_hash = ?", (ip_hash,)
            ).fetchone()
            if count >= MAX_SITES_PER_IP:
                db.execute("ROLLBACK")
                return False
            db.execute("INSERT INTO sites (slug, ip_hash) VALUES (?, ?)", (slug, ip_hash))
            db.execute("COMMIT")
            return True
        except Exception:
            db.execute("ROLLBACK")
            raise


def release_site(slug: str) -> None:
    with closing(get_db()) as db:
        db.execute("DELETE FROM sites WHERE slug = ?", (slug,))


# ---------------------------------------------------------------------------
# Site helpers
# ---------------------------------------------------------------------------
def make_slug(value: str) -> str:
    """Return a URL-friendly site name, never a path."""
    value = secure_filename(value.strip().lower())
    value = re.sub(r"[^a-z0-9_-]+", "-", value).strip("-_")
    return value[:60]


def site_exists(slug: str) -> bool:
    if (UPLOAD_FOLDER / slug).is_dir():
        return True
    with closing(get_db()) as db:
        return db.execute("SELECT 1 FROM sites WHERE slug = ?", (slug,)).fetchone() is not None


def unique_slug(slug: str) -> str:
    candidate = slug
    while site_exists(candidate):
        candidate = f"{slug}-{secrets.token_hex(2)}"
    return candidate


def safe_zip_members(zf: zipfile.ZipFile):
    """Validate archive paths and size before extracting anything."""
    members = zf.infolist()
    if len(members) > MAX_ZIP_FILES:
        raise ValueError(f"ZIP has too many entries (maximum {MAX_ZIP_FILES}).")

    total_size = 0
    safe_members = []
    for info in members:
        # ZIP names use forward slashes. Reject absolute paths, traversal,
        # Windows drive paths, and symlinks.
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or not name or any(part in ("..", "") for part in path.parts):
            raise ValueError("ZIP contains an unsafe file path.")
        if path.parts and ":" in path.parts[0]:
            raise ValueError("ZIP contains an unsafe file path.")

        unix_mode = (info.external_attr >> 16) & 0xFFFF
        if (unix_mode & 0o170000) == 0o120000:
            raise ValueError("ZIP symlinks are not allowed.")

        total_size += info.file_size
        if total_size > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("ZIP expands beyond the 100 MB extraction limit.")

        safe_members.append((info, path))
    return safe_members


def extract_site_zip(zip_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        members = safe_zip_members(zf)
        for info, relative_path in members:
            target = destination.joinpath(*relative_path.parts).resolve()
            if target != destination.resolve() and destination.resolve() not in target.parents:
                raise ValueError("ZIP contains a path outside the site folder.")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def find_homepage(site_dir: Path) -> Path | None:
    """Find index.html at the root or in a single wrapper folder."""
    root_index = site_dir / "index.html"
    if root_index.is_file():
        return root_index

    # Conveniently handle ZIPs that contain one top-level project folder.
    children = list(site_dir.iterdir())
    if len(children) == 1 and children[0].is_dir():
        nested_index = children[0] / "index.html"
        if nested_index.is_file():
            return nested_index
    return None


def prepare_site_root(site_dir: Path) -> Path:
    """If a ZIP has one wrapper folder containing index.html, serve that folder."""
    homepage = find_homepage(site_dir)
    if homepage is None:
        raise ValueError("No index.html found. Put index.html in the ZIP root (or one top-level folder).")
    return homepage.parent


HOME_TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0b1020">
  <title>SimpleHost — Publish your site</title>
  <style>
    :root{color-scheme:dark;--bg:#090d18;--panel:#11182a;--line:#263149;--muted:#9ba8c4;--text:#f4f7ff;--accent:#8b7cff;--cyan:#55dfc0}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 12% 0%,#22234b 0,transparent 38%),radial-gradient(ellipse at 100% 20%,#103a3b 0,transparent 30%),var(--bg);font:16px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;color:var(--text)}
    a{color:inherit}.wrap{width:min(1050px,calc(100% - 36px));margin:auto}.nav{display:flex;align-items:center;justify-content:space-between;padding:26px 0}.brand{display:flex;gap:11px;align-items:center;font-size:19px;font-weight:800;letter-spacing:-.5px}.logo{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--cyan));color:#07121a;font-weight:900}.pill{border:1px solid var(--line);border-radius:999px;padding:8px 13px;color:#c9d2e8;font-size:13px}
    .hero{padding:58px 0 34px;max-width:760px}.eyebrow{color:var(--cyan);font-size:12px;font-weight:800;letter-spacing:2px;text-transform:uppercase}.hero h1{font-size:clamp(42px,7vw,76px);line-height:1.02;letter-spacing:-3px;margin:17px 0}.gradient{background:linear-gradient(90deg,#fff,#b7b1ff 52%,#74f0d1);color:transparent;background-clip:text}.hero p{max-width:610px;color:var(--muted);font-size:18px;margin:0}
    .layout{display:grid;grid-template-columns:1.2fr .8fr;gap:20px;margin:20px 0 70px}.card{background:linear-gradient(160deg,rgba(20,29,49,.96),rgba(14,20,35,.96));border:1px solid var(--line);border-radius:22px;padding:28px;box-shadow:0 24px 70px #0002}.card h2{font-size:20px;margin:0 0 8px}.sub{color:var(--muted);font-size:14px;margin:0 0 22px}.field{display:block;font-size:13px;color:#d9e1f5;font-weight:700;margin:18px 0 8px}.input{width:100%;padding:14px 15px;background:#090f1d;border:1px solid #303b55;border-radius:12px;color:var(--text);font:inherit;outline:none}.input:focus{border-color:var(--accent);box-shadow:0 0 0 3px #8b7cff26}.drop{display:block;text-align:center;border:1px dashed #586786;border-radius:16px;padding:25px 16px;background:#0a1120;cursor:pointer;transition:.2s}.drop:hover,.drop.drag{border-color:var(--cyan);background:#0c2028}.drop .up{font-size:28px}.drop strong{display:block;margin:7px 0}.drop small{color:var(--muted)}input[type=file]{display:none}.btn{width:100%;border:0;border-radius:12px;padding:15px 18px;margin-top:18px;background:linear-gradient(100deg,#9383ff,#63e7ce);color:#07121a;font-size:15px;font-weight:850;cursor:pointer}.btn:hover{filter:brightness(1.08);transform:translateY(-1px)}.hint{color:var(--muted);font-size:12px;margin:12px 0 0}.notice{border:1px solid #31584f;background:#102923;color:#b5ffe9;border-radius:12px;padding:12px 14px;margin:0 0 16px;font-size:14px}.notice.error{border-color:#6e3b4c;background:#2c1721;color:#ffc6d3}.feature{display:flex;gap:14px;padding:17px 0;border-bottom:1px solid #273149}.feature:last-child{border:0}.feature-icon{width:39px;height:39px;flex-shrink:0;border-radius:12px;display:grid;place-items:center;background:#202744;font-size:18px}.feature b{display:block;font-size:14px}.feature span{display:block;color:var(--muted);font-size:13px;margin-top:3px}.foot{padding:0 0 30px;color:#6f7d9b;font-size:12px;display:flex;justify-content:space-between;gap:15px}
    @media(max-width:760px){.layout{grid-template-columns:1fr}.hero{padding-top:35px}.card{padding:22px}.hero h1{letter-spacing:-2px}.foot{flex-direction:column}}
  </style>
</head>
<body><div class="wrap">
  <nav class="nav"><div class="brand"><span class="logo">S</span> SimpleHost</div><span class="pill">✦ Static site hosting</span></nav>
  <header class="hero"><div class="eyebrow">Your idea, online</div><h1>Ship your site.<br><span class="gradient">Skip the setup.</span></h1><p>Upload your HTML file or a complete website ZIP. We’ll give it its own folder and a shareable link in seconds.</p></header>
  <main class="layout">
    <section class="card">
      <h2>Publish a website</h2><p class="sub">Choose a name and upload your site files.</p>
      {% for category, msg in get_flashed_messages(with_categories=true) %}
        <div class="notice {{ 'error' if category == 'error' else '' }}">{{ msg }}</div>
      {% endfor %}
      <form id="uploadForm" method="POST" enctype="multipart/form-data">
        <label class="field" for="site_name">Website name</label>
        <input class="input" id="site_name" name="site_name" placeholder="e.g. my-portfolio" minlength="1" maxlength="60" required>
        <label class="field">Website files</label>
        <label class="drop" id="dropzone" for="file">
          <div class="up">⇧</div><strong id="fileTitle">Drop your files here</strong>
          <small id="fileInfo">or click to browse · .html or .zip · max 50 MB</small>
        </label>
        <input id="file" type="file" name="file" accept=".html,.zip,text/html,application/zip,application/x-zip-compressed" required>
        <button class="btn" type="submit">Publish website <span aria-hidden="true">→</span></button>
        <p class="hint">ZIP should include an <code>index.html</code>. Images, CSS and JavaScript are supported.</p>
      </form>
    </section>
    <aside class="card">
      <h2>Everything in one place</h2><p class="sub">A simple path from files to a live link.</p>
      <div class="feature"><div class="feature-icon">▣</div><div><b>One folder per site</b><span>Each project gets its own isolated directory.</span></div></div>
      <div class="feature"><div class="feature-icon">↗</div><div><b>Shareable URLs</b><span>Publish to simplehost.onrender.com/your-name.</span></div></div>
      <div class="feature"><div class="feature-icon">▧</div><div><b>Assets stay together</b><span>HTML, images, stylesheets and scripts keep their paths.</span></div></div>
      <div class="feature"><div class="feature-icon">⌁</div><div><b>Ready for mobile</b><span>A clean upload experience on desktop and phone.</span></div></div>
    </aside>
  </main>
  <footer class="foot"><span>© SimpleHost · Publish something good.</span><span>Static HTML hosting</span></footer>
</div>
<script>
const input=document.getElementById('file'), zone=document.getElementById('dropzone');
const title=document.getElementById('fileTitle'), info=document.getElementById('fileInfo');
function showFile(file){if(!file)return;title.textContent=file.name;info.textContent=(file.size/1024/1024).toFixed(2)+' MB · ready to upload';}
input.addEventListener('change',()=>showFile(input.files[0]));
zone.addEventListener('dragover',e=>{e.preventDefault();zone.classList.add('drag')});
zone.addEventListener('dragleave',()=>zone.classList.remove('drag'));
zone.addEventListener('drop',e=>{e.preventDefault();zone.classList.remove('drag');if(e.dataTransfer.files.length){input.files=e.dataTransfer.files;showFile(input.files[0]);}});
document.getElementById('uploadForm').addEventListener('submit',e=>{const f=input.files[0];if(f&&f.size>50*1024*1024){e.preventDefault();alert('The upload must be smaller than 50 MB.');}});
</script></body></html>
"""

SUCCESS_TEMPLATE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Published · SimpleHost</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#090d18;color:#f4f7ff;font:16px/1.6 system-ui,sans-serif;padding:24px}.card{width:min(620px,100%);padding:clamp(25px,6vw,48px);border:1px solid #263149;border-radius:24px;background:linear-gradient(150deg,#151d32,#101626);box-shadow:0 25px 80px #0004}.check{display:grid;place-items:center;width:56px;height:56px;border-radius:18px;background:#10352d;color:#72f2cb;font-size:28px}h1{font-size:clamp(30px,6vw,44px);letter-spacing:-1.5px;line-height:1.1;margin:24px 0 10px}p{color:#9ba8c4}.url{display:block;overflow-wrap:anywhere;padding:15px;background:#090f1d;border:1px solid #303b55;border-radius:12px;color:#72f2cb;margin:22px 0}.btn{display:inline-block;text-decoration:none;background:linear-gradient(100deg,#9383ff,#63e7ce);color:#07121a;font-weight:800;padding:13px 18px;border-radius:11px;margin:4px 8px 4px 0}.secondary{color:#dce3f5;text-decoration:none;padding:12px}
</style></head><body><main class="card"><div class="check">✓</div><h1>Your website is live.</h1><p>Your files have been published in their own site folder.</p><a class="url" href="{{ site_url }}">{{ site_url }}</a><a class="btn" href="{{ site_url }}" target="_blank" rel="noopener">Open website ↗</a><a class="secondary" href="{{ url_for('index') }}">Publish another</a></main></body></html>
"""


@app.errorhandler(413)
def too_large(_error):
    flash("That upload is too large. The maximum file size is 50 MB.", "error")
    return redirect(url_for("index"))


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        uploaded = request.files.get("file")
        site_name = request.form.get("site_name", "")
        if not uploaded or not uploaded.filename:
            flash("Choose an HTML file or ZIP first.", "error")
            return redirect(url_for("index"))

        extension = Path(uploaded.filename).suffix.lower()
        if extension not in ALLOWED_UPLOADS:
            flash("Only .html and .zip files are supported.", "error")
            return redirect(url_for("index"))

        slug = make_slug(site_name)
        if not slug:
            flash("Enter a site name using letters or numbers.", "error")
            return redirect(url_for("index"))

        slug = unique_slug(slug)

        # Enforce the per-IP quota before touching the disk.
        try:
            reserved = reserve_site(client_id(), slug)
        except sqlite3.IntegrityError:
            flash("That name was just taken. Please try again.", "error")
            return redirect(url_for("index"))
        if not reserved:
            flash(
                f"Limit reached: you can publish up to {MAX_SITES_PER_IP} websites per IP address.",
                "error",
            )
            return redirect(url_for("index"))

        destination = UPLOAD_FOLDER / slug
        temp_zip = None

        try:
            destination.mkdir(parents=True, exist_ok=False)

            if extension == ".html":
                (destination / "index.html").write_bytes(uploaded.read())
            else:
                # Store the archive outside the public site directory.
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp:
                    temp_zip = Path(temp.name)
                    uploaded.save(temp.name)
                if not zipfile.is_zipfile(temp_zip):
                    raise ValueError("The uploaded file is not a valid ZIP archive.")
                extract_site_zip(temp_zip, destination)

            # Make sure there's a usable index.html (root or single wrapper folder).
            prepare_site_root(destination)
            return redirect(url_for("published", site_name=slug))
        except (ValueError, zipfile.BadZipFile, OSError) as exc:
            shutil.rmtree(destination, ignore_errors=True)
            release_site(slug)  # failed uploads don't use up a slot
            flash(str(exc) if str(exc) else "Could not process this upload.", "error")
            return redirect(url_for("index"))
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            release_site(slug)
            raise
        finally:
            if temp_zip:
                temp_zip.unlink(missing_ok=True)

    return render_template_string(HOME_TEMPLATE)


@app.route("/published/<site_name>")
def published(site_name):
    slug = make_slug(site_name)
    site_dir = UPLOAD_FOLDER / slug
    if not site_dir.is_dir():
        abort(404)
    try:
        prepare_site_root(site_dir)
    except ValueError:
        abort(404)
    site_url = request.url_root.rstrip("/") + url_for("serve_site", site_name=slug)
    return render_template_string(SUCCESS_TEMPLATE, site_url=site_url)


@app.route("/<site_name>/", defaults={"asset_path": ""})
@app.route("/<site_name>/<path:asset_path>")
def serve_site(site_name, asset_path):
    # Only serve files inside a published site's resolved root.
    slug = make_slug(site_name)
    site_dir = UPLOAD_FOLDER / slug
    if not slug or not site_dir.is_dir():
        abort(404)
    try:
        site_root = prepare_site_root(site_dir)
    except ValueError:
        abort(404)

    if not asset_path:
        asset_path = "index.html"

    requested = (site_root / asset_path).resolve()
    if requested != site_root.resolve() and site_root.resolve() not in requested.parents:
        abort(404)
    if not requested.is_file():
        abort(404)

    relative = requested.relative_to(site_root.resolve()).as_posix()
    # send_from_directory applies an additional safe-path check.
    return send_from_directory(str(site_root), relative, conditional=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
