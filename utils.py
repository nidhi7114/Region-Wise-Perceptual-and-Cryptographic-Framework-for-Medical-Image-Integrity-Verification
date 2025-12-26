# utils.py
import os
import sqlite3
import random
from PIL import Image, ImageDraw
import imagehash
from datetime import datetime

# ----------------- Total Hamming Distance -----------------
def total_hamming_distance(hash_list1, hash_list2):
    """
    Computes total Hamming distance between two lists of perceptual hashes.
    Each hash is expected to be a hex string.
    """
    return sum(imagehash.hex_to_hash(h1) - imagehash.hex_to_hash(h2)
               for h1, h2 in zip(hash_list1, hash_list2))

# ----------------- Region-aware Perceptual Hash -----------------
def region_aware_phash(image, grid_size=(3, 3)):
    """
    Compute region-aware perceptual hash for an image.
    Returns a list of hashes (hex strings) for each region.
    """
    if isinstance(image, str):
        image = Image.open(image).convert("L")
    else:
        image = image.convert("L")

    w, h = image.size
    gw, gh = grid_size
    region_w, region_h = w // gw, h // gh

    hashes = []
    for i in range(gw):
        for j in range(gh):
            region = image.crop((i * region_w, j * region_h, (i + 1) * region_w, (j + 1) * region_h))
            hashes.append(str(imagehash.phash(region)))
    return hashes

# ----------------- Allowed File Check -----------------
def allowed_file(filename, allowed_extensions={'png', 'jpg', 'jpeg', 'bmp'}):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# ----------------- Audit Logging -----------------
def add_audit(filename, user, action, result):
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO audit_logs (filename, user, action, result, timestamp) VALUES (?, ?, ?, ?, ?)',
        (filename, user, action, result, datetime.now())
    )
    conn.commit()
    conn.close()

# ----------------- Tamper Simulation -----------------
def tamper_image(image):
    """
    Randomly tamper a region of the image to simulate modification.
    """
    image = image.copy()
    draw = ImageDraw.Draw(image)
    w, h = image.size

    # Random rectangle
    rect_w = random.randint(w // 10, w // 4)
    rect_h = random.randint(h // 10, h // 4)
    x1 = random.randint(0, w - rect_w)
    y1 = random.randint(0, h - rect_h)
    x2, y2 = x1 + rect_w, y1 + rect_h

    # Fill rectangle with random color
    fill = random.randint(0, 255)
    draw.rectangle([x1, y1, x2, y2], fill=fill)
    return image
