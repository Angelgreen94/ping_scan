from collections import deque
from pathlib import Path
from PIL import Image


source = Path("app_icon_source.png")
target = Path("app_icon.ico")

img = Image.open(source).convert("RGBA")
pixels = img.load()
width, height = img.size


def is_background(pixel):
    r, g, b, a = pixel
    if a == 0:
        return True
    return r > 215 and g > 215 and b > 215 and abs(r - g) < 18 and abs(g - b) < 18


visited = set()
queue = deque()
for x in range(width):
    queue.append((x, 0))
    queue.append((x, height - 1))
for y in range(height):
    queue.append((0, y))
    queue.append((width - 1, y))

while queue:
    x, y = queue.popleft()
    if (x, y) in visited or x < 0 or y < 0 or x >= width or y >= height:
        continue
    visited.add((x, y))
    if not is_background(pixels[x, y]):
        continue
    pixels[x, y] = (255, 255, 255, 0)
    queue.append((x + 1, y))
    queue.append((x - 1, y))
    queue.append((x, y + 1))
    queue.append((x, y - 1))

bbox = img.getbbox()
if bbox:
    img = img.crop(bbox)

size = max(img.size)
canvas = Image.new("RGBA", (size, size), (255, 255, 255, 0))
canvas.alpha_composite(img, ((size - img.width) // 2, (size - img.height) // 2))

icon_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
canvas.save(target, format="ICO", sizes=icon_sizes)
print(str(target.resolve()))
