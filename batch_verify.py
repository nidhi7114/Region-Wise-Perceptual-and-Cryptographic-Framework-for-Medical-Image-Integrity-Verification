# batch_verify.py
import os
from PIL import Image, UnidentifiedImageError
import imagehash
from utils import region_aware_phash, add_audit

HAMMING_THRESHOLD = 2  # Threshold to decide tampering

def batch_verify(orig_dir, tampered_dir):
    summary = []

    orig_files = sorted(os.listdir(orig_dir))
    tampered_files = sorted(os.listdir(tampered_dir))

    for orig_file in orig_files:
        orig_path = os.path.join(orig_dir, orig_file)
        try:
            orig_img = Image.open(orig_path).convert('L')
            orig_hashes = region_aware_phash(orig_img)
        except UnidentifiedImageError:
            summary.append({
                "original": orig_file,
                "matched_tampered": None,
                "tampered": None,
                "hamming": None,
                "error": "Cannot open original image"
            })
            continue

        best_match_file = None
        best_distance = float('inf')
        tampered_status = None

        # Compare with all tampered images
        for tam_file in tampered_files:
            tam_path = os.path.join(tampered_dir, tam_file)
            try:
                tam_img = Image.open(tam_path).convert('L')
                tam_hashes = region_aware_phash(tam_img)
            except UnidentifiedImageError:
                continue

            # Compute total region-wise Hamming distance
            distance = sum(
                imagehash.hex_to_hash(r1) - imagehash.hex_to_hash(r2)
                for r1, r2 in zip(orig_hashes, tam_hashes)
            )

            # Keep the closest match
            if distance < best_distance:
                best_distance = distance
                best_match_file = tam_file
                tampered_status = 'Yes' if distance > HAMMING_THRESHOLD else 'No'

        # Append results
        summary.append({
            "original": orig_file,
            "matched_tampered": best_match_file,
            "tampered": tampered_status,
            "hamming": best_distance if best_match_file else None,
            "error": None if best_match_file else "No matching tampered image"
        })

        # Add audit log
        add_audit(orig_file, "admin", "batch_verify", tampered_status if best_match_file else "error")

    return summary
