# app.py (revised)
import os
import uuid
import sqlite3
import base64
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, jsonify, current_app
)
from werkzeug.utils import secure_filename
from PIL import Image, UnidentifiedImageError
from ecdsa import SigningKey, VerifyingKey, NIST384p
import imagehash
import csv

# Try to import helpers from utils; if missing, provide small fallbacks
try:
    from utils import region_aware_phash, allowed_file, add_audit, tamper_image
except Exception:
    def allowed_file(filename, allowed_exts={'png','jpg','jpeg','bmp'}):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_exts

    def add_audit(filename, user, action, result):
        conn = sqlite3.connect('images.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO audit_logs (filename, user, action, result) VALUES (?, ?, ?, ?)',
                       (filename, user, action, result))
        conn.commit()
        conn.close()

    def tamper_image(image):
        from PIL import ImageDraw
        import random
        img = image.copy()
        draw = ImageDraw.Draw(img)
        w, h = img.size
        rect_w, rect_h = w // 10, h // 10
        x, y = random.randint(0, max(0, w-rect_w)), random.randint(0, max(0, h-rect_h))
        draw.rectangle([x, y, x + rect_w, y + rect_h], fill='black')
        return img

# ----------------- Flask App Setup -----------------
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
HAMMING_THRESHOLD = 1  # you can tune this for experiments

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs("results", exist_ok=True)  # For batch results

# ----------------- Database Initialization -----------------
def init_db():
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT, original_filename TEXT,
        phash TEXT, region_hashes TEXT,
        signature BLOB, last_distance INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT, user TEXT,
        action TEXT, result TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

# ----------------- Load or Generate ECDSA Keys -----------------
from ecdsa import SigningKey, VerifyingKey, NIST384p

PRIVATE_KEY_PATH = "ecdsa_private.pem"
PUBLIC_KEY_PATH = "ecdsa_public.pem"

if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = SigningKey.from_pem(f.read())
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = VerifyingKey.from_pem(f.read())
    print("[ECDSA] Keys loaded from disk.")
else:
    private_key = SigningKey.generate(curve=NIST384p)
    public_key = private_key.get_verifying_key()
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.to_pem())
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.to_pem())
    print("[ECDSA] Keys generated and saved to disk.")
        
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}

# ----------------- Helpers -----------------
def compute_region_hex_hashes(image, grid_size=3):
    """
    Given a PIL Image, split into grid_size x grid_size, compute phash for each region,
    and return a list of hex-string hashes (strings).
    """
    if isinstance(grid_size, int):
        gw = gh = grid_size
    else:
        gw, gh = grid_size

    w, h = image.size
    region_w = w // gw
    region_h = h // gh

    hashes = []
    for i in range(gh):
        for j in range(gw):
            left = j * region_w
            top = i * region_h
            # ensure the last region covers the border pixels
            right = (j + 1) * region_w if j < gw - 1 else w
            bottom = (i + 1) * region_h if i < gh - 1 else h
            region = image.crop((left, top, right, bottom)).convert('L')
            hval = imagehash.phash(region)
            hashes.append(str(hval))
    return hashes

def total_hamming_distance(hex_list_a, hex_list_b):
    """Compute sum of region Hamming distances (uses imagehash objects)."""
    return sum(imagehash.hex_to_hash(a) - imagehash.hex_to_hash(b) for a, b in zip(hex_list_a, hex_list_b))

# ----------------- Routes -----------------
@app.route('/')
def index():
    files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if allowed_file(f)]
    return render_template('index.html', title="Perceptual Hashing with ECDSA", uploaded_files=files)

# ----------------- Single Upload -----------------
@app.route('/upload', methods=['POST'])
def upload_image():
    file = request.files.get('image')
    if not file or file.filename == '' or not allowed_file(file.filename):
        flash('Invalid file', 'danger')
        return redirect(url_for('index'))

    original_filename = secure_filename(file.filename)
    # open image and compute region hashes
    image = Image.open(file).convert('L')
    region_hex = compute_region_hex_hashes(image, grid_size=3)  # fixed 3x3 by default
    phash = ','.join(region_hex)  # canonical string that we sign/store

    # Check duplicates by hamming distance against stored region hashes
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    cursor.execute('SELECT filename, region_hashes FROM images')
    existing_records = cursor.fetchall()

    for stored_filename, stored_region_hashes in existing_records:
        stored_list = stored_region_hashes.split(',')
        # compute total Hamming distance
        try:
            distance = total_hamming_distance(region_hex, stored_list)
        except Exception:
            # in case stored format broken, skip
            continue
        if distance <= HAMMING_THRESHOLD:
            flash(f"Duplicate image detected! Already uploaded as {stored_filename}", "warning")
            conn.close()
            return redirect(url_for('index'))

    # Save image to uploads
    stored_filename = f"{uuid.uuid4().hex}_{original_filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    file.seek(0)
    file.save(path)

    # Sign canonical phash string
    signature = private_key.sign(phash.encode())

    cursor.execute(
        'INSERT INTO images (filename, original_filename, phash, region_hashes, signature, last_distance) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (stored_filename, original_filename, phash, ','.join(region_hex), signature, 0)
    )
    conn.commit()
    conn.close()

    add_audit(original_filename, "admin", "upload", "success")
    region_status = [(h, 'match') for h in region_hex]

    return render_template(
        'result.html',
        title="Image Signed Successfully",
        uploaded=stored_filename,
        hash_value=phash,
        signature_b64=base64.b64encode(signature).decode(),
        mode='upload',
        region_status=region_status,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

# ----------------- Single Verification -----------------
@app.route('/verify', methods=['POST'])
def verify_image():
    file = request.files.get('image')
    if not file or file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    temp_filename = f"{uuid.uuid4().hex}_{filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    file.save(path)

    try:
        image = Image.open(path)
    except UnidentifiedImageError:
        flash("Invalid image file", "danger")
        os.remove(path)
        return redirect(url_for('index'))

    region_hex = compute_region_hex_hashes(image, grid_size=3)
    new_phash_str = ','.join(region_hex)

    # fetch stored images
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, filename, region_hashes, signature FROM images')
    records = cursor.fetchall()

    best_match = None
    best_distance = float('inf')
    for rec_id, stored_filename, stored_region_hashes, stored_sig in records:
        stored_list = stored_region_hashes.split(',')
        # ensure same number of regions before zip; if not, skip stored record
        if len(stored_list) != len(region_hex):
            continue
        distance = total_hamming_distance(region_hex, stored_list)
        if distance < best_distance:
            best_distance = distance
            best_match = (rec_id, stored_filename, stored_list, stored_sig)

    tampered = True
    region_status = []
    ref_filename = None

    if best_match:
        rec_id, ref_filename, stored_list, stored_sig = best_match
        # per-region status
        region_status = [
            (h_new, 'match' if imagehash.hex_to_hash(h_new) == imagehash.hex_to_hash(h_stored) else 'mismatch')
            for h_new, h_stored in zip(region_hex, stored_list)
        ]
        try:
            # verify signature: note we sign the canonical comma-joined hex string
            public_key.verify(stored_sig, new_phash_str.encode())
            # signature valid → decide tampering by Hamming threshold
            tampered = best_distance > HAMMING_THRESHOLD
        except Exception:
            tampered = True

        cursor.execute('UPDATE images SET last_distance=? WHERE id=?', (best_distance, rec_id))
        conn.commit()

    add_audit(filename, "admin", "verify", "untampered" if not tampered else "tampered")
    conn.close()

    return render_template(
        'result.html',
        title="Verification Result",
        uploaded=temp_filename,
        reference=ref_filename,
        tampered=tampered,
        stored_phash=','.join(best_match[2]) if best_match else None,
        hash_value=new_phash_str,
        hamming=best_distance,
        region_status=region_status,
        mode='verify',
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

# ----------------- API Verification -----------------
@app.route('/verify_api', methods=['POST'])
def verify_api():
    file = request.files.get('image')
    if not file or file.filename == '':
        return jsonify({"error": "No file provided"}), 400

    filename = secure_filename(file.filename)
    temp_filename = f"{uuid.uuid4().hex}_{filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    file.save(path)

    try:
        image = Image.open(path)
    except UnidentifiedImageError:
        return jsonify({"error": "Invalid image file"}), 400

    region_hex = compute_region_hex_hashes(image, grid_size=3)
    new_phash_str = ','.join(region_hex)

    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, filename, region_hashes, signature FROM images')
    records = cursor.fetchall()

    best_match = None
    best_distance = float('inf')
    for rec_id, stored_filename, stored_region_hashes, stored_sig in records:
        stored_list = stored_region_hashes.split(',')
        if len(stored_list) != len(region_hex):
            continue
        distance = total_hamming_distance(region_hex, stored_list)
        if distance < best_distance:
            best_distance = distance
            best_match = (rec_id, stored_filename, stored_list, stored_sig)

    tampered = True
    region_status = []
    ref_filename = None

    if best_match:
        rec_id, ref_filename, stored_list, stored_sig = best_match
        region_status = [
            {"hash": h_new, "status": "match" if imagehash.hex_to_hash(h_new) == imagehash.hex_to_hash(h_stored) else "mismatch"}
            for h_new, h_stored in zip(region_hex, stored_list)
        ]
        try:
            public_key.verify(stored_sig, new_phash_str.encode())
            tampered = best_distance > HAMMING_THRESHOLD
        except Exception:
            tampered = True
        cursor.execute('UPDATE images SET last_distance=? WHERE id=?', (best_distance, rec_id))
        conn.commit()

    add_audit(filename, "api_user", "verify_api", "untampered" if not tampered else "tampered")
    conn.close()

    return jsonify({
        "uploaded": temp_filename,
        "reference": ref_filename,
        "tampered": tampered,
        "hamming_distance": best_distance,
        "region_status": region_status
    })

# ----------------- Batch Verification -----------------
@app.route('/batch_upload', methods=['POST'])
def batch_upload():
    orig_files = request.files.getlist('original_images')
    tampered_files = request.files.getlist('tampered_images')

    if not orig_files or not tampered_files:
        flash("Please upload both original and tampered images", "danger")
        return redirect(url_for('index'))

    # Directories to save batch files
    orig_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'batch_original')
    tampered_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'batch_tampered')
    os.makedirs(orig_dir, exist_ok=True)
    os.makedirs(tampered_dir, exist_ok=True)

    # Save uploaded files
    for f in orig_files:
        f.save(os.path.join(orig_dir, f.filename))
    for f in tampered_files:
        f.save(os.path.join(tampered_dir, f.filename))

    # List of filenames
    orig_list = [f for f in os.listdir(orig_dir) if allowed_file(f, ALLOWED_EXTENSIONS)]
    tampered_list = [f for f in os.listdir(tampered_dir) if allowed_file(f, ALLOWED_EXTENSIONS)]

    # Helper: match tampered file to original
    def match_tampered(orig_filename, tampered_files):
        orig_base, _ = os.path.splitext(orig_filename)
        for t in tampered_files:
            t_base, _ = os.path.splitext(t)
            if orig_base.lower() in t_base.lower() or t_base.lower() in orig_base.lower():
                return t
        return None

    total_tampered = 0
    total_not_tampered = 0
    summary = []

    for orig in orig_list:
        orig_path = os.path.join(orig_dir, orig)
        tampered_file = match_tampered(orig, tampered_list)

        if not tampered_file:
            summary.append({
                "original": orig,
                "matched_tampered": None,
                "tampered": None,
                "hamming": None,
                "error": "No matching tampered file"
            })
            continue

        tampered_path = os.path.join(tampered_dir, tampered_file)

        try:
            # Compute region hashes
            orig_img = Image.open(orig_path).convert('L')
            tampered_img = Image.open(tampered_path).convert('L')

            orig_hashes = compute_region_hex_hashes(orig_img, grid_size=3)
            tampered_hashes = compute_region_hex_hashes(tampered_img, grid_size=3)

            # Per-region mismatch detection
            
            mismatch_count = sum(
                imagehash.hex_to_hash(h1) != imagehash.hex_to_hash(h2)
                for h1, h2 in zip(orig_hashes, tampered_hashes)
            )
            mismatch_ratio = mismatch_count / len(orig_hashes)
            # Calculate average Hamming distance
            hamming_values = [
                imagehash.hex_to_hash(h1) - imagehash.hex_to_hash(h2)
                for h1, h2 in zip(orig_hashes, tampered_hashes)
            ]
            avg_hamming = sum(hamming_values) / len(hamming_values)

            # Decide tampering
            is_tampered = mismatch_ratio > 0.3 or avg_hamming > HAMMING_THRESHOLD
            if is_tampered:
                total_tampered += 1
            else:
                total_not_tampered += 1

            summary.append({
                "original": orig,
                "matched_tampered": tampered_file,
                "tampered": "Tampered" if is_tampered else "Not Tampered",
                "hamming": round(avg_hamming, 2),
                "mismatch_ratio": round(mismatch_ratio, 2),
                "error": "-"
            })

        except Exception as e:
            summary.append({
                "original": orig,
                "matched_tampered": tampered_file,
                "tampered": None,
                "hamming": None,
                "mismatch_ratio": round(mismatch_ratio, 2),
                "error": str(e)
            })

    add_audit("batch_verify", "admin", "batch_upload", "completed")

    batch_stats = {
        "total_images": len(orig_list),
        "total_tampered": total_tampered,
        "total_not_tampered": total_not_tampered
    }

    export_batch_summary(summary)
    return render_template(
        'batch_result.html',
        summary=summary,
        batch_stats=batch_stats,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

# ----------------- Simulate Tamper (existing) -----------------
@app.route('/simulate_tamper', methods=['POST'])
def simulate_tamper_post():
    filename = request.form.get('filename')
    if not filename:
        flash("No filename provided!", "danger")
        return redirect(url_for('index'))

    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(path):
        flash(f"File not found: {filename}", "danger")
        return redirect(url_for('index'))

    try:
        image = Image.open(path)
    except Exception as e:
        flash(f"Cannot open image: {e}", "danger")
        return redirect(url_for('index'))

    tampered_img = tamper_image(image)
    tampered_filename = f"tampered_{filename}"
    tampered_path = os.path.join(app.config['UPLOAD_FOLDER'], tampered_filename)
    tampered_img.save(tampered_path)

    region_hex = compute_region_hex_hashes(tampered_img, grid_size=3)
    phash = ','.join(region_hex)
    region_status = [(h, 'mismatch') for h in region_hex]

    flash(f"Tampered image saved as {tampered_filename}", "success")
    return render_template(
        'result.html',
        title="Tampered Image",
        uploaded=tampered_filename,
        hash_value=phash,
        tampered=True,
        region_status=region_status,
        mode='tamper',
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def export_batch_summary(summary, filename="results/batch_summary.csv"):
    keys = ["original", "matched_tampered", "tampered", "hamming", "mismatch_ratio", "error"]
    with open(filename, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(summary)

# ----------------- Run -----------------
if __name__ == '__main__':
    app.run(debug=True)
