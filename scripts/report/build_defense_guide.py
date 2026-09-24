"""Convert the reviewed defense-guide Markdown to the shared OpenXML block schema."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[2]
source = ROOT / 'docs/defense/快速答辩指南.md'
lines = source.read_text().splitlines()
blocks = []
i = 4  # Title, metadata and separating blank lines are rendered by the cover-free header.
while i < len(lines):
    line = lines[i]
    if not line.strip():
        i += 1
        continue
    if line == '<!-- page -->':
        blocks.append({'type':'page'})
    elif line.startswith('```'):
        code = []
        i += 1
        while i < len(lines) and not lines[i].startswith('```'):
            code.append(lines[i]); i += 1
        blocks.append({'type':'code','text':'\n'.join(code)})
    elif line.startswith('## '):
        blocks.append({'type':'h','level':1,'text':line[3:]})
    elif line.startswith('### '):
        blocks.append({'type':'h','level':2,'text':line[4:]})
    elif line.startswith('!['):
        caption=line.split(']')[0][2:]
        blocks.append({'type':'image','path':'docs/diagrams/architecture.png','caption':caption})
    elif line.startswith('|'):
        rows = []
        while i < len(lines) and lines[i].startswith('|'):
            rows.append([x.strip() for x in lines[i].strip('|').split('|')]); i += 1
        caption = blocks.pop()['text']
        widths = [3700,5326] if len(rows[0])==2 else [1900,700,6426]
        blocks.append({'type':'table','caption':caption,'headers':rows[0],'rows':rows[2:],'widths':widths})
        continue
    else:
        blocks.append({'type':'p','text':line})
    i += 1
spec={'title':'ASTHONEY 快速答辩指南','kind':'本机 Agent SSH 探测 三页速查','author':'第14组 · 刘毅凡答辩速查 · 2026年9月23日','cover':False,'compact':True,'filename':'第14组 ASTHONEY 快速答辩指南.docx','blocks':blocks}
(ROOT/'docs/defense/guide.json').write_text(json.dumps(spec,ensure_ascii=False,indent=2)+'\n')
print(f'Prepared {len(blocks)} blocks')
