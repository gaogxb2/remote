import re

ANSI_PATTERN = re.compile(r'\033(?:\033\[|\[)([0-9;]*)m')
ANSI_FG_COLORS = {
    30: "#000000",
    31: "#FF0000",
    32: "#00FF00",
    33: "#FFFF00",
    34: "#0000FF",
    35: "#FF00FF",
    36: "#00FFFF",
    37: "#FFFFFF",
}

def parse_segments(text):
    segments = []
    current_fg = "#FFFFFF"
    current_bg = None
    last_pos = 0

    for match in ANSI_PATTERN.finditer(text):
        if match.start() > last_pos:
            segment_text = text[last_pos:match.start()]
            segments.append((segment_text, current_fg, current_bg))
        code_str = match.group(1)
        if not code_str:
            current_fg = "#FFFFFF"
            current_bg = None
        else:
            for part in code_str.split(';'):
                if not part:
                    continue
                code = int(part)
                if code == 0:
                    current_fg = "#FFFFFF"
                    current_bg = None
                elif code == 1:
                    continue
                elif 30 <= code <= 37:
                    current_fg = ANSI_FG_COLORS.get(code, "#FFFFFF")
        last_pos = match.end()

    if last_pos < len(text):
        segments.append((text[last_pos:], current_fg, current_bg))
    return segments

if __name__ == "__main__":
    sample = "\033[1;34mbin\033[m \033[1;34metc\033[m"
    parts = parse_segments(sample)
    for idx, (content, fg, bg) in enumerate(parts, 1):
        print(f"Segment {idx}: text={content!r}, fg={fg}, bg={bg}")
