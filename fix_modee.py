import os, glob

for filepath in glob.glob('wardenips/**/*.py', recursive=True) + ['main.py']:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    if 'modee' in content:
        new_content = content.replace('modee', 'mode')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Fixed 'modee' typo in {filepath}")
