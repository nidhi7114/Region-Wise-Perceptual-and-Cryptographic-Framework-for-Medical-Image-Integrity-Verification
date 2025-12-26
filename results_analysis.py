import os
import time
import hashlib
import pandas as pd
from PIL import Image
import imagehash
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report

from utils import region_aware_phash, total_hamming_distance

# --- Config ---
ORIG_DIR = "dataset/original/images"
TAMPER_DIR = "dataset/tampered"
RESULT_DIR = "results"
FULL_DIR = os.path.join(RESULT_DIR, "full_results")
PLOT_DIR = os.path.join(RESULT_DIR, "mr_distributions")
GRID_SIZES = [(3, 3), (4, 4), (8, 8)]
HAMMING_THRESHOLDS = [1.0, 2.0, 3.0]
MISMATCH_THRESHOLD = 0.3
TAMPER_TYPES = ["crop", "blur", "contrast", "brightness", "copy_move", "noise"]

os.makedirs(FULL_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)

# --- Utilities ---
def load_image(path):
    try: return Image.open(path).convert('L')
    except: return None

def compute_region_hashes(image, grid_size):
    return region_aware_phash(image, grid_size)

def compute_global_phash(image):
    return imagehash.phash(image)

def compute_md5(path):
    with open(path, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

def compute_sha256(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def compare_region_hashes(orig_hashes, tam_hashes):
    hd = total_hamming_distance(orig_hashes, tam_hashes)
    mr = sum(imagehash.hex_to_hash(h1) != imagehash.hex_to_hash(h2)
             for h1, h2 in zip(orig_hashes, tam_hashes)) / len(orig_hashes)
    return round(hd, 2), round(mr, 2)

def match_originals(orig_list, tamper_list):
    matches = []
    for orig in orig_list[:500]:
        base = os.path.splitext(orig)[0]
        for tam in tamper_list:
            if base.lower() in tam.lower():
                matches.append((orig, tam))
                break
    return matches

# --- Analysis ---
def analyze_pair(orig_path, tam_path, grid_size, threshold):
    orig_img = load_image(orig_path)
    tam_img = load_image(tam_path)
    if not orig_img or not tam_img:
        return None

    orig_region = compute_region_hashes(orig_img, grid_size)
    tam_region = compute_region_hashes(tam_img, grid_size)
    hd, mr = compare_region_hashes(orig_region, tam_region)
    region_verdict = "Tampered" if hd > threshold or mr > MISMATCH_THRESHOLD else "Not Tampered"

    global_hd = compute_global_phash(orig_img) - compute_global_phash(tam_img)
    md5_changed = compute_md5(orig_path) != compute_md5(tam_path)
    sha_changed = compute_sha256(orig_path) != compute_sha256(tam_path)

    return {
        "original": os.path.basename(orig_path),
        "tampered": os.path.basename(tam_path),
        "region_hd": hd,
        "region_mr": mr,
        "region_verdict": region_verdict,
        "global_phash_diff": global_hd,
        "md5_changed": md5_changed,
        "sha256_changed": sha_changed
    }

def analyze_tamper_type(tamper_type, grid_size, threshold):
    orig_files = sorted(os.listdir(ORIG_DIR))[:500]
    tamper_files = sorted(os.listdir(os.path.join(TAMPER_DIR, tamper_type)))
    pairs = match_originals(orig_files, tamper_files)

    results = []
    start = time.time()
    for orig, tam in pairs:
        orig_path = os.path.join(ORIG_DIR, orig)
        tam_path = os.path.join(TAMPER_DIR, tamper_type, tam)
        result = analyze_pair(orig_path, tam_path, grid_size, threshold)
        if result:
            result.update({
                "tamper_type": tamper_type,
                "grid": f"{grid_size[0]}×{grid_size[1]}",
                "threshold": threshold
            })
            results.append(result)
    print(f"⏱️ {tamper_type} @ {grid_size} / {threshold}: {time.time() - start:.2f}s")
    return results

# --- Experiment Sweep ---
def run_experiments():
    all_experiments = []
    baseline_metrics = []

    for grid in GRID_SIZES:
        for thresh in HAMMING_THRESHOLDS:
            all_results = []
            for tamper_type in TAMPER_TYPES:
                all_results.extend(analyze_tamper_type(tamper_type, grid, thresh))

            df = pd.DataFrame(all_results)
            df["is_actual_tampered"] = df["tamper_type"] != "original"
            df["is_predicted_tampered"] = df["region_verdict"] == "Tampered"

            # Region-aware metrics
            y_true = df["is_actual_tampered"]
            y_pred = df["is_predicted_tampered"]
            report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)

            all_experiments.append({
                "grid": f"{grid[0]}×{grid[1]}",
                "threshold": thresh,
                "accuracy": report["accuracy"],
                "precision": report["True"]["precision"],
                "recall": report["True"]["recall"],
                "f1": report["True"]["f1-score"],
                "avg_mr": round(df["region_mr"].mean(), 3),
                "avg_hd": round(df["region_hd"].mean(), 2)
            })

            # Baseline metrics
            for method in ["global_phash_diff", "md5_changed", "sha256_changed"]:
                if method == "global_phash_diff":
                    df["baseline_pred"] = df[method] > 5
                else:
                    df["baseline_pred"] = df[method]

                y_pred_base = df["baseline_pred"]
                report_base = classification_report(y_true, y_pred_base, output_dict=True, zero_division=0)
                baseline_metrics.append({
                    "grid": f"{grid[0]}×{grid[1]}",
                    "threshold": thresh,
                    "method": method,
                    "accuracy": report_base["accuracy"],
                    "precision": report_base["True"]["precision"],
                    "recall": report_base["True"]["recall"],
                    "f1": report_base["True"]["f1-score"]
                })

            # Save results
            df.to_csv(f"{FULL_DIR}/grid_{grid[0]}_thresh_{thresh}.csv", index=False)

            # Plot MR
            plt.hist(df["region_mr"], bins=10, color='skyblue', edgecolor='black')
            plt.title(f"MR Distribution ({grid[0]}×{grid[1]}, Thresh={thresh})")
            plt.xlabel("Mismatch Ratio")
            plt.ylabel("Frequency")
            plt.savefig(f"{PLOT_DIR}/mr_grid_{grid[0]}_thresh_{thresh}.png")
            plt.clf()

    pd.DataFrame(all_experiments).to_csv(f"{RESULT_DIR}/experiment_summary.csv", index=False)
    pd.DataFrame(baseline_metrics).to_csv(f"{RESULT_DIR}/baseline_comparison.csv", index=False)

    # MR by tamper type
    df_all = pd.concat([pd.read_csv(f"{FULL_DIR}/grid_{g[0]}_thresh_{t}.csv")
                        for g in GRID_SIZES for t in HAMMING_THRESHOLDS])
    mr_summary = df_all.groupby(["grid", "threshold", "tamper_type"]).agg({
        "region_mr": ["mean", "max", "min"],
        "region_hd": "mean"
    }).round(2)
    mr_summary.columns = ["avg_mr", "max_mr", "min_mr", "avg_hd"]
    mr_summary.reset_index(inplace=True)
    mr_summary.to_csv(f"{RESULT_DIR}/mr_by_tamper_type.csv", index=False)

if __name__ == "__main__":
    run_experiments()