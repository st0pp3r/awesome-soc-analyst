import os
import re
from html import escape
from datetime import datetime

# Get the current date and time
current_time = datetime.now()
human_readable_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

# Input Markdown file
README_FILE = "README.md"

# Output file
BOOKMARKS_FILE = "bookmarks.html"

def parse_markdown_to_links(markdown_file):
    """Parse the Markdown file and extract links organized by sections and subsections."""
    with open(markdown_file, "r", encoding="utf-8") as f:
        content = f.read()

    links_by_section = {}
    current_section = None
    current_subsection = None

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("### "):  # Main section
            current_section = line.lstrip("# ").strip()
            current_subsection = None  # Reset subsection when a new main section appears
            if current_section not in ["Contents"]:
                links_by_section[current_section] = {}
        elif line.startswith("#### "):  # Subsection
            if current_section:
                current_subsection = line.lstrip("# ").strip()
                if current_subsection:
                    links_by_section[current_section][current_subsection] = []
        elif line.startswith("- [") and "](http" in line:  # Link line
            matches = re.findall(r"\[([^\]]+)\]\((http[s]?://[^\)]+)\)", line)
            for match in matches:
                if match:
                    url, name = match[1], match[0]
                    if current_section:
                        if current_subsection:
                            links_by_section[current_section][current_subsection].append((url, name))
                        else:
                            if current_section not in links_by_section:
                                links_by_section[current_section] = []
                            links_by_section[current_section].append((url, name))

    # Sort links alphabetically within each section/subsection
    for section, content in links_by_section.items():
        if isinstance(content, dict):  # If it has subsections
            for subsection in content:
                content[subsection].sort(key=lambda x: x[1].lower())
        elif isinstance(content, list):
            content.sort(key=lambda x: x[1].lower())

    return links_by_section

def create_bookmark_html(links_by_section, title):
    """Generate an HTML file for browser bookmarks with nested subsections."""
    html = [
        f"<!--Generated datetime: {escape(human_readable_time)}-->",
        "<!DOCTYPE NETSCAPE-Bookmark-file-1>",
        "<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">",
        f"<TITLE>{escape(title)}</TITLE>",
        f"<H1>{escape(title)}</H1>",
        "<DL><p>",
        "  <DT><H3>Awesome SOC Analyst</H3>",
        "  <DL><p>"
    ]

    for section, content in links_by_section.items():
        html.append(f"    <DT><H3>{escape(section)}</H3>")
        html.append("    <DL><p>")
        
        if isinstance(content, dict):  # It has subsections
            for subsection, links in content.items():
                html.append(f"      <DT><H4>{escape(subsection)}</H4>")
                html.append("      <DL><p>")
                for url, name in links:
                    html.append(f"        <DT><A HREF=\"{escape(url)}\">{escape(name)}</A>")
                html.append("      </DL><p>")
        elif isinstance(content, list):  # It only contains links
            for url, name in content:
                html.append(f"      <DT><A HREF=\"{escape(url)}\">{escape(name)}</A>")

        html.append("    </DL><p>")

    html.append("  </DL><p>")
    html.append("</DL><p>")

    return "\n".join(html)

def main():
    if not os.path.exists(README_FILE):
        print(f"Error: {README_FILE} does not exist.")
        return
    
    links_by_section = parse_markdown_to_links(README_FILE)

    # Generate bookmarks
    bookmarks_html = create_bookmark_html(links_by_section, "Browser Bookmarks")
    with open(BOOKMARKS_FILE, "w", encoding="utf-8") as f:
        f.write(bookmarks_html)

    print(f"Bookmarks generated: {BOOKMARKS_FILE}")

if __name__ == "__main__":
    main()
