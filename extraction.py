import tarfile
import os

tar_path = 'images_01.tar.gz'
output_dir = 'dataset/original/'
os.makedirs(output_dir, exist_ok=True)

with tarfile.open(tar_path) as tar:
    tar.extractall(path=output_dir)

print("Extraction complete.") 
'''
import os

folder = 'dataset\original'
images = []
for root, dirs, files in os.walk(folder):
    for f in files:
        if f.lower().endswith(('.png', '.jpg', '.jpeg')):
            images.append(os.path.join(root, f))

print(f"Number of images extracted (including subfolders): {len(images)}") '''


