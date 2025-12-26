import os
import argparse
import random
import csv
from PIL import Image, ImageFilter, ImageEnhance
import numpy as np

# Supported image formats
IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.bmp', '.tiff')

def tamper_image(image, tamper_type, crop_fraction=0.2, noise_intensity=20):
    w, h = image.size

    if tamper_type == 'crop':
        left = int(random.uniform(0, crop_fraction) * w)
        top = int(random.uniform(0, crop_fraction) * h)
        right = int(w - random.uniform(0, crop_fraction) * w)
        bottom = int(h - random.uniform(0, crop_fraction) * h)
        return image.crop((left, top, right, bottom)).resize((w, h))

    elif tamper_type == 'blur':
        return image.filter(ImageFilter.GaussianBlur(radius=3))

    elif tamper_type == 'contrast':
        factor = random.uniform(0.5, 1.5)
        return ImageEnhance.Contrast(image).enhance(factor)

    elif tamper_type == 'brightness':
        factor = random.uniform(0.5, 1.5)
        return ImageEnhance.Brightness(image).enhance(factor)

    elif tamper_type == 'copy_move':
        box_size = (w // 5, h // 5)
        x1, y1 = random.randint(0, w - box_size[0]), random.randint(0, h - box_size[1])
        region = image.crop((x1, y1, x1 + box_size[0], y1 + box_size[1]))
        x2, y2 = random.randint(0, w - box_size[0]), random.randint(0, h - box_size[1])
        image.paste(region, (x2, y2))
        return image

    elif tamper_type == 'noise':
        image_np = np.array(image)
        noise = np.random.normal(0, noise_intensity, image_np.shape).astype(np.uint8)
        image_np = np.clip(image_np + noise, 0, 255)
        return Image.fromarray(image_np)

    else:
        return image  # No tampering

def main(args):
    os.makedirs(args.output_dir, exist_ok=True)
    tamper_types = args.tamper_types.split(',') if args.tamper_types else ['crop', 'blur', 'contrast', 'brightness', 'copy_move', 'noise']
    images = [f for f in os.listdir(args.input_dir) if f.lower().endswith(IMAGE_EXTENSIONS)]

    # Initialize counter per tamper type
    counters = {t: 0 for t in tamper_types}

    log_path = os.path.join(args.output_dir, 'tamper_log.csv')
    with open(log_path, 'w', newline='') as logfile:
        writer = csv.writer(logfile)
        writer.writerow(['Original Filename', 'Tampered Filename', 'Tamper Type'])

        for img_file in images:
            # If all types reached 500, stop processing originals
            if all(count >= 500 for count in counters.values()):
                print("Reached 500 images per tamper type. Stopping.")
                break

            img_path = os.path.join(args.input_dir, img_file)
            image = Image.open(img_path)

            for tamper_type in tamper_types:
                # Skip if this tamper type already has 500 images
                if counters[tamper_type] >= 500:
                    continue

                tampered = tamper_image(image.copy(), tamper_type, args.crop_fraction, args.noise_intensity)
                tamper_subdir = os.path.join(args.output_dir, tamper_type)
                os.makedirs(tamper_subdir, exist_ok=True)

                tampered_filename = f"{tamper_type}_{img_file}"
                tampered_path = os.path.join(tamper_subdir, tampered_filename)
                tampered.save(tampered_path)

                writer.writerow([img_file, tampered_filename, tamper_type])
                counters[tamper_type] += 1
                print(f"{img_file} → {tamper_type} ({counters[tamper_type]}/500)")

    print("Tampering complete. Final counts:", counters)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate tampered versions of medical images for integrity testing.")
    parser.add_argument('--input-dir', type=str, required=True, help='Path to original images')
    parser.add_argument('--output-dir', type=str, required=True, help='Path to save tampered images')
    parser.add_argument('--tamper-types', type=str, default=None, help='Comma-separated tamper types (e.g., crop,blur,noise)')
    parser.add_argument('--crop-fraction', type=float, default=0.2, help='Fraction to crop for crop tampering')
    parser.add_argument('--noise-intensity', type=int, default=20, help='Noise intensity for noise tampering')

    args = parser.parse_args()
    main(args)
