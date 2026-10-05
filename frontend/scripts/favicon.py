#!/usr/bin/env python3
"""Oddjob favicon: a bowler hat, drawn to survive 16x16.

Drawn at 16x scale and downsampled, because the only thing that matters is
what the 16px tab icon looks like -- everything else is a byproduct.

Proportions are the whole job. The first attempt read as a flying saucer:
the crown was tall and narrow, the brim was 2.2x the crown width, and there
was a cyan glow under the brim that looked like a tractor beam. A bowler is
the opposite shape -- a low DOMED crown, a brim only ~1.5x the crown width,
and the two touching with no gap.
"""
from PIL import Image, ImageDraw

S = 64          # logical canvas
K = 16          # supersample factor
W = S * K

# Synthwave palette, same as the app's default theme.
PINK = (255, 126, 219)
PINK_HI = (255, 196, 240)
PINK_LO = (198, 74, 170)
CYAN = (94, 234, 240)
INK = (26, 16, 40)


#: Everything is laid out on a 64-unit grid and then blown up about the
#: centre to fill the frame. At 16px every unused pixel of margin is 6%
#: of the icon's width thrown away, so the hat runs nearly edge to edge.
ZOOM = 1.26


def k(*v):
    return [(32 + (x - 32) * ZOOM) * K for x in v]


def draw(bg=None):
    im = Image.new("RGBA", (W, W), bg or (0, 0, 0, 0))
    d = ImageDraw.Draw(im)

    # --- brim -------------------------------------------------------
    # 44 wide against a 26-wide crown: 1.7x. Wider than this and the
    # silhouette turns into a disc with a bump on it.
    d.ellipse(k(10, 38, 54, 50), fill=PINK_LO)
    d.ellipse(k(10, 36, 54, 48), fill=PINK)
    # Leading edge catches the light.
    d.arc(k(10, 36, 54, 48), 200, 340, fill=PINK_HI, width=2 * K)

    # --- crown ------------------------------------------------------
    # Dome, not a box: a rounded rect with a radius equal to half its
    # width IS a dome at the top, and the straight sides below give the
    # bowler its flat-sided look.
    d.rounded_rectangle(k(19, 17, 45, 42), radius=13 * K, fill=PINK)
    # Square off the bottom so the crown meets the brim with no notch.
    d.rectangle(k(19, 34, 45, 42), fill=PINK)
    # Shade the right third -- a solid pink blob has no volume at 32px.
    d.rounded_rectangle(k(36, 18, 45, 42), radius=6 * K, fill=PINK_LO)
    d.rectangle(k(36, 34, 45, 42), fill=PINK_LO)
    # Highlight on the left shoulder of the dome.
    d.arc(k(20, 18, 40, 38), 185, 265, fill=PINK_HI, width=2 * K)

    # --- hatband ----------------------------------------------------
    # Sits ON the crown, above the brim line, which is what reads as
    # "bowler" rather than "mound".
    d.rectangle(k(19, 33, 45, 38), fill=CYAN)
    d.rectangle(k(19, 36, 45, 38), fill=(60, 180, 190))

    # Brim overlaps the band's bottom edge so they interlock.
    d.ellipse(k(10, 36, 54, 48), outline=PINK, width=K // 2)

    return im.resize((S, S), Image.LANCZOS)


def flat(im, bg):
    out = Image.new("RGBA", im.size, bg)
    out.alpha_composite(im)
    return out


if __name__ == "__main__":
    import sys
    base = draw()
    out = sys.argv[1] if len(sys.argv) > 1 else "."

    # iOS composites a transparent touch icon onto flat black and squares
    # off the corners itself. Giving it the theme's ink colour makes that
    # background a decision rather than a default.
    flat(base.resize((180, 180), Image.LANCZOS), INK).save(
        f"{out}/apple-touch-icon.png")
    base.resize((32, 32), Image.LANCZOS).save(f"{out}/favicon-32.png")
    base.save(f"{out}/favicon.ico",
              sizes=[(16, 16), (32, 32), (48, 48)])

    # Contact sheet: the actual sizes, on the backgrounds a tab bar uses.
    sizes = [16, 24, 32, 48]
    sheet = Image.new("RGB", (4 * 110 + 20, 3 * 110 + 20), (40, 40, 44))
    for row, bg in enumerate([(32, 28, 38), (248, 248, 250)]):
        for col, n in enumerate(sizes):
            cell = Image.new("RGB", (100, 100), bg)
            ic = flat(base.resize((n, n), Image.LANCZOS), bg).convert("RGB")
            cell.paste(ic, ((100 - n) // 2, (100 - n) // 2))
            sheet.paste(cell, (20 + col * 110, 20 + row * 110))
    # Bottom row: 16px blown up with nearest, to see the actual pixels.
    for col, n in enumerate(sizes):
        ic = flat(base.resize((n, n), Image.LANCZOS), (32, 28, 38))
        sheet.paste(ic.resize((100, 100), Image.NEAREST).convert("RGB"),
                    (20 + col * 110, 20 + 2 * 110))
    sheet.save("/tmp/favicon-check.png")
    print("rendered")
