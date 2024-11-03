import os

# Define the pages in a separate data structure
pages = [
    {
        "filename": "index.md",
        "title": "Home",
        "content": """# Welcome to Rusty JWT
This is the home page for Rusty JWT documentation."""
    },
    {
        "filename": "installation.md",
        "title": "Installation",
        "content": """# Installation
Instructions on how to install Rusty JWT."""
    },
    {
        "filename": "usage.md",
        "title": "Usage",
        "content": """# Usage
How to use Rusty JWT."""
    },
    {
        "filename": "api.md",
        "title": "API Reference",
        "content": """# API Reference
Detailed API documentation for Rusty JWT."""
    },
]

def create_jekyll_markdown(pages, output_dir="."):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for index, page in enumerate(pages, start=1):
        file_path = os.path.join(output_dir, page["filename"])
        try:
            with open(file_path, "w") as f:
                f.write(f"""---
layout: default
title: {page['title']}
index: {index}
---

{page['content']}
""")
            print(f"Created {file_path}")
        except IOError as e:
            print(f"Error writing to {file_path}: {e}")

# Call the function with the pages data and specify the output directory
create_jekyll_markdown(pages, output_dir=".")