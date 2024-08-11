import re

version = None

def fix_up(file):
    global version
    if version is None:
        version =  open('VERSION').read().split()[0]
    content = open(file).read()
    content_fix_up = re.sub(
        '''^__version__ = ['"][^'"]*['"]$''',
        f"__version__ = '{version}'",
        content, 1, re.MULTILINE
    )
    if content_fix_up != content:
        print('Version tag has been changed, now updating...')
        open(file, 'w', newline='\n').write(content_fix_up)
        print('Version tag has been updated.')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Fix up the version in giving file.')
    parser.add_argument('file', nargs='?', default='memimport.py', help='File path.')
    args = parser.parse_args()
    fix_up(args.file)
