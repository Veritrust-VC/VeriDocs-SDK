#!/usr/bin/env python3
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path


def extract_txt(data: bytes) -> str:
    return data.decode('utf-8', errors='ignore')


def extract_docx(path: Path) -> str:
    out = []
    with zipfile.ZipFile(path, 'r') as zf:
        with zf.open('word/document.xml') as f:
            root = ET.fromstring(f.read())
        for node in root.iter():
            if node.tag.endswith('}t') and node.text:
                out.append(node.text)
    return '\n'.join(out)


def extract_odt(path: Path) -> str:
    out = []
    with zipfile.ZipFile(path, 'r') as zf:
        with zf.open('content.xml') as f:
            root = ET.fromstring(f.read())
        for node in root.iter():
            if node.text and node.tag.endswith('}p'):
                out.append(node.text)
    return '\n'.join(out)


def extract_rtf(data: bytes) -> str:
    text = data.decode('utf-8', errors='ignore')
    text = re.sub(r'\\par[d]?', '\n', text)
    text = re.sub(r'\\[a-z]+-?\d* ?', '', text)
    text = re.sub(r'[{}]', '', text)
    return text


def _decode_pdf_literal(value: str) -> str:
    return value.replace('\\(', '(').replace('\\)', ')').replace('\\n', '\n')


def extract_pdf(data: bytes) -> str:
    parts = []
    for raw in re.findall(rb'stream\r?\n(.*?)\r?\nendstream', data, flags=re.S):
        stream = raw
        try:
            stream = zlib.decompress(raw)
        except Exception:
            pass
        decoded = stream.decode('latin-1', errors='ignore')
        for m in re.findall(r'\((.*?)\)\s*Tj', decoded, flags=re.S):
            parts.append(_decode_pdf_literal(m))
    return '\n'.join(parts)


def main():
    if len(sys.argv) < 2:
      print(json.dumps({'error': 'missing file'}))
      sys.exit(1)

    path = Path(sys.argv[1])
    suffix = path.suffix.lower()
    data = path.read_bytes()

    text = ''
    if suffix == '.txt':
        text = extract_txt(data)
    elif suffix == '.docx':
        text = extract_docx(path)
    elif suffix == '.odt':
        text = extract_odt(path)
    elif suffix == '.rtf':
        text = extract_rtf(data)
    elif suffix == '.pdf':
        text = extract_pdf(data)

    print(json.dumps({'text': text.strip(), 'format': suffix}))


if __name__ == '__main__':
    main()
