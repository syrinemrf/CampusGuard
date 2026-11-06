"""Generates docs/diagrams/usecases.svg (UML-style use case diagram)."""
import html
OUT = '/mnt/user-data/outputs/s2/docs/diagrams/usecases.svg'
W, H = 1250, 880
BX, BY, BW, BH = 265, 20, 760, 810
OX, OW, OH = 565, 380, 42           # oval centre x, width, height
UC = [  # id, label, planned
    ('UC0', "S'authentifier", False), ('UC1', 'Importer un fichier CSV / JSON / TXT', False),
    ("UC2", "Consulter l'aperçu et la validation", False), ('UC3', "Suivre le statut d'ingestion", False),
    ('UC13', 'Indexer les événements', False), ('UC4', 'Rechercher et filtrer les logs', False),
    ('UC5', "Consulter le détail d'un événement", False), ('UC6', 'Exporter en CSV', False),
    ('UC7', 'Consulter les tableaux de bord et Kibana', False), ('UC8', 'Personnaliser son tableau de bord', False),
    ('UC9', "Appeler l'API REST (Swagger)", False), ('UC10', 'Gérer alertes et incidents (prévu)', True),
    ('UC11', 'Bloquer une IP en laboratoire (prévu)', True), ('UC12', 'Suivre le flux en temps réel (prévu)', True)]
y0, step = 82, 54
pos = {u[0]: (OX, y0 + i * step) for i, u in enumerate(UC)}
actors = {'A': ('Analyste SOC', 80, 330), 'D': ('Administrateur', 80, 560), 'U': ('Auditeur', 80, 745)}
links = {'A': ['UC0', 'UC1', 'UC3', 'UC4', 'UC5', 'UC6', 'UC7', 'UC8', 'UC9', 'UC10', 'UC11', 'UC12'],
         'D': ['UC0', 'UC1', 'UC4', 'UC7', 'UC9', 'UC10', 'UC11'],
         'U': ['UC0', 'UC4', 'UC5', 'UC6', 'UC7', 'UC8']}
colors = {'A': '#2b6cb0', 'D': '#b7791f', 'U': '#2f855a'}
e = html.escape
o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="DejaVu Sans, Arial, sans-serif">',
     '<defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#555"/></marker></defs>',
     f'<rect width="{W}" height="{H}" fill="white"/>',
     f'<rect x="{BX}" y="{BY}" width="{BW}" height="{BH}" rx="10" fill="#f7f9fc" stroke="#12355b" stroke-width="2"/>',
     f'<text x="{BX + BW / 2}" y="{BY + 22}" text-anchor="middle" font-size="15" font-weight="bold" fill="#12355b">Système CampusGuard / Sentinel</text>']
# actor-usecase lines first (below ovals)
for key, ids in links.items():
    _, ax, ay = actors[key]
    for uid in ids:
        ux, uy = pos[uid]
        o.append(f'<line x1="{ax + 22}" y1="{ay}" x2="{ux - OW / 2 + 6}" y2="{uy}" stroke="{colors[key]}" stroke-width="1.2" opacity="0.65"/>')
# system actor Logstash on the right
lx, ly = 1150, pos['UC13'][1]
o.append(f'<line x1="{lx - 22}" y1="{ly}" x2="{OX + OW / 2 - 6}" y2="{ly}" stroke="#718096" stroke-width="1.4"/>')
# include / extend arrows on the right side of ovals
def arrow(frm, to, label, dx):
    x1, y1 = pos[frm]; x2, y2 = pos[to]
    xr = OX + OW / 2
    o.append(f'<path d="M{xr - 30} {y1 + 8} C {xr + dx} {y1 + 8}, {xr + dx} {y2}, {xr - 4} {y2}" fill="none" stroke="#555" stroke-width="1.3" stroke-dasharray="6 4" marker-end="url(#ar)"/>')
    o.append(f'<text x="{xr + dx - 4}" y="{(y1 + y2) / 2 + 4}" font-size="11" fill="#444" text-anchor="start" font-style="italic">{e(label)}</text>')
arrow('UC1', 'UC2', '«include»', 40)
arrow('UC1', 'UC3', '«include»', 62)
arrow('UC1', 'UC13', '«déclenche»', 84)
def extend(frm, to):  # extension: base UC <- extending UC (arrow from extending to base)
    x1, y1 = pos[frm]; x2, y2 = pos[to]
    xl = OX - OW / 2
    o.append(f'<path d="M{xl + 30} {y1 - 8} C {xl - 36} {y1 - 8}, {xl - 36} {y2}, {xl + 4} {y2}" fill="none" stroke="#555" stroke-width="1.3" stroke-dasharray="6 4" marker-end="url(#ar)"/>')
    o.append(f'<text x="{xl - 62}" y="{(y1 + y2) / 2 + 4}" font-size="11" fill="#444" font-style="italic">«extend»</text>')
extend('UC5', 'UC4')
extend('UC11', 'UC10')
# ovals
for uid, label, planned in UC:
    x, y = pos[uid]
    fill, stroke, dash = ('#edf2f7', '#718096', ' stroke-dasharray="5 3"') if planned else ('#ffffff', '#12355b', '')
    o.append(f'<ellipse cx="{x}" cy="{y}" rx="{OW / 2}" ry="{OH / 2}" fill="{fill}" stroke="{stroke}" stroke-width="1.6"{dash}/>')
    o.append(f'<text x="{x}" y="{y + 4.5}" text-anchor="middle" font-size="12.5" fill="#1b2430">{e(label)}</text>')
# actors
def stick(x, y, label, color):
    o.append(f'<g stroke="{color}" stroke-width="2.2" fill="none"><circle cx="{x}" cy="{y - 36}" r="10" fill="white"/><line x1="{x}" y1="{y - 26}" x2="{x}" y2="{y + 6}"/>'
             f'<line x1="{x - 18}" y1="{y - 16}" x2="{x + 18}" y2="{y - 16}"/><line x1="{x}" y1="{y + 6}" x2="{x - 14}" y2="{y + 28}"/><line x1="{x}" y1="{y + 6}" x2="{x + 14}" y2="{y + 28}"/></g>')
    o.append(f'<text x="{x}" y="{y + 46}" text-anchor="middle" font-size="13" font-weight="bold" fill="{color}">{e(label)}</text>')
for key, (label, ax, ay) in actors.items():
    stick(ax, ay, label, colors[key])
stick(lx, ly - 6, 'Logstash', '#4a5568')
o.append(f'<text x="{lx}" y="{ly + 56}" text-anchor="middle" font-size="11" fill="#4a5568">(système d’ingestion)</text>')
o.append(f'<text x="30" y="{H - 12}" font-size="11" fill="#555">Ovales en pointillés gris = cas d’utilisation prévus (S4–S5), non implémentés.</text>')
o.append('</svg>')
open(OUT, 'w', encoding='utf-8').write('\n'.join(o))
print('ok')
