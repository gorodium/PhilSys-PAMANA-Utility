from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter


ROOT = Path(__file__).resolve().parent.parent
ASSET_DIR = ROOT / "assets"
PNG_PATH = ASSET_DIR / "nas_transfer_icon.png"
ICO_PATH = ASSET_DIR / "nas_transfer_icon.ico"


def rounded_rectangle_gradient(size, radius, top_color, bottom_color):
    width, height = size
    gradient = Image.new("RGBA", size)
    pixels = gradient.load()

    for y in range(height):
        ratio = y / max(height - 1, 1)
        color = tuple(
            int(top_color[index] * (1 - ratio) + bottom_color[index] * ratio)
            for index in range(4)
        )
        for x in range(width):
            pixels[x, y] = color

    mask = Image.new("L", size, 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, width - 1, height - 1), radius=radius, fill=255)
    gradient.putalpha(mask)
    return gradient


def draw_icon(size=1024):
    scale = size / 1024
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    shadow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    shadow_draw = ImageDraw.Draw(shadow)
    margin = int(72 * scale)
    radius = int(190 * scale)
    shadow_draw.rounded_rectangle(
        (margin, margin + int(18 * scale), size - margin, size - margin + int(18 * scale)),
        radius=radius,
        fill=(0, 0, 0, 70),
    )
    image.alpha_composite(shadow.filter(ImageFilter.GaussianBlur(int(26 * scale))))

    tile = rounded_rectangle_gradient(
        (size - margin * 2, size - margin * 2),
        radius,
        (17, 78, 137, 255),
        (12, 132, 145, 255),
    )
    image.alpha_composite(tile, (margin, margin))

    draw = ImageDraw.Draw(image)

    # Back plate: a quiet institutional mark that still reads at small sizes.
    draw.rounded_rectangle(
        (int(302 * scale), int(250 * scale), int(722 * scale), int(744 * scale)),
        radius=int(74 * scale),
        fill=(255, 255, 255, 28),
        outline=(255, 255, 255, 92),
        width=max(2, int(7 * scale)),
    )

    left_box = (int(212 * scale), int(350 * scale), int(448 * scale), int(598 * scale))
    right_box = (int(576 * scale), int(350 * scale), int(812 * scale), int(598 * scale))
    for box in (left_box, right_box):
        draw.rounded_rectangle(
            box,
            radius=int(50 * scale),
            fill=(246, 250, 252, 255),
            outline=(188, 235, 241, 255),
            width=max(2, int(8 * scale)),
        )
        x1, y1, x2, y2 = box
        for offset in (72, 124, 176):
            y = y1 + int(offset * scale)
            draw.line(
                (x1 + int(58 * scale), y, x2 - int(58 * scale), y),
                fill=(22, 100, 143, 255),
                width=max(3, int(12 * scale)),
            )

    arrow_color = (31, 217, 175, 255)
    arrow_shadow = (4, 55, 77, 120)
    line_width = max(18, int(44 * scale))
    draw.arc(
        (int(336 * scale), int(260 * scale), int(688 * scale), int(544 * scale)),
        start=199,
        end=341,
        fill=arrow_shadow,
        width=line_width + max(4, int(8 * scale)),
    )
    draw.arc(
        (int(336 * scale), int(260 * scale), int(688 * scale), int(544 * scale)),
        start=199,
        end=341,
        fill=arrow_color,
        width=line_width,
    )
    draw.polygon(
        [
            (int(692 * scale), int(352 * scale)),
            (int(616 * scale), int(320 * scale)),
            (int(640 * scale), int(406 * scale)),
        ],
        fill=arrow_color,
    )

    draw.arc(
        (int(336 * scale), int(420 * scale), int(688 * scale), int(704 * scale)),
        start=19,
        end=161,
        fill=arrow_shadow,
        width=line_width + max(4, int(8 * scale)),
    )
    draw.arc(
        (int(336 * scale), int(420 * scale), int(688 * scale), int(704 * scale)),
        start=19,
        end=161,
        fill=(255, 204, 92, 255),
        width=line_width,
    )
    draw.polygon(
        [
            (int(332 * scale), int(612 * scale)),
            (int(408 * scale), int(646 * scale)),
            (int(384 * scale), int(558 * scale)),
        ],
        fill=(255, 204, 92, 255),
    )

    # Small secure-transfer accent.
    shield = [
        (int(512 * scale), int(662 * scale)),
        (int(604 * scale), int(700 * scale)),
        (int(586 * scale), int(812 * scale)),
        (int(512 * scale), int(858 * scale)),
        (int(438 * scale), int(812 * scale)),
        (int(420 * scale), int(700 * scale)),
    ]
    draw.polygon(shield, fill=(246, 250, 252, 255))
    draw.line(
        (
            int(474 * scale),
            int(756 * scale),
            int(505 * scale),
            int(792 * scale),
            int(558 * scale),
            int(724 * scale),
        ),
        fill=(12, 132, 145, 255),
        width=max(7, int(22 * scale)),
        joint="curve",
    )

    return image


def main():
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    image = draw_icon()
    image.save(PNG_PATH)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    icon_images = [image.resize((size, size), Image.Resampling.LANCZOS) for size in sizes]
    icon_images[-1].save(ICO_PATH, sizes=[(size, size) for size in sizes], append_images=icon_images[:-1])
    print(PNG_PATH)
    print(ICO_PATH)


if __name__ == "__main__":
    main()
