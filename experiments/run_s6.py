"""Lance les deux expériences S6 et écrit les résultats (JSON + figures) dans docs/experiments/.

    python experiments/run_s6.py                       # télécharge le journal Loghub si absent
    MINILM_DIR=/chemin/vers/all-MiniLM-L6-v2 python experiments/run_s6.py   # ajoute MiniLM (model.onnx + tokenizer.json)

Dépendances : requirements-ml.txt (scikit-learn, matplotlib ; onnxruntime + tokenizers pour MiniLM ; drain3).
"""
import argparse
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
BASE_URL = 'https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/'
FILES = ('OpenSSH_2k.log', 'OpenSSH_2k.log_structured.csv')


def fetch(raw_dir):
    raw_dir.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        if not (raw_dir / name).exists():
            urllib.request.urlretrieve(BASE_URL + name, raw_dir / name)


def figures(anom, tmpl, out):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    cyan, uv, red, ink = '#0aa9a0', '#6a4cf0', '#e0344f', '#0d1730'
    plt.rcParams.update({'font.size': 9, 'axes.spines.top': False, 'axes.spines.right': False, 'axes.edgecolor': '#9aa5b8'})

    fig, ax = plt.subplots(1, 2, figsize=(9.5, 3.4))
    pr = anom['pr_curve']
    ax[0].plot(pr['recall'], pr['precision'], color=uv, lw=2, label=f"Isolation Forest (AP = {anom['average_precision']})")
    for key, label, color in (('rules', 'Règles', cyan), ('isolation_forest', 'IF au seuil 1 %', uv), ('hybrid', 'Règles + IF', ink)):
        r = anom[key]
        ax[0].scatter(r['recall'], r['precision'], s=55, color=color, zorder=3, label=f"{label} (F1 {r['f1']})")
    ax[0].set(xlabel='Rappel', ylabel='Précision', xlim=(0, 1.02), ylim=(0, 1.05), title='Fenêtres (IP, 5 min)')
    ax[0].legend(fontsize=7.5, loc='lower left', frameon=False)
    s = anom['scores']
    bins = 30
    ax[1].hist(s['normal'], bins=bins, color=cyan, alpha=.7, label='trafic légitime')
    ax[1].hist(s['attack'], bins=bins, color=red, alpha=.7, label='attaques réelles')
    ax[1].axvline(s['threshold'], color=ink, ls='--', lw=1)
    ax[1].text(s['threshold'], ax[1].get_ylim()[1] * .9, ' seuil', fontsize=8)
    ax[1].set(xlabel='Score d’anomalie', ylabel='Fenêtres', title='Séparation des scores')
    ax[1].legend(fontsize=7.5, frameon=False)
    fig.tight_layout()
    fig.savefig(out / 's6_anomaly.png', dpi=160)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    colors = {'TF-IDF, brut': '#9ad9d4', 'TF-IDF, masqué': cyan, 'MiniLM, brut': '#c4b8f7', 'MiniLM, masqué': uv}
    for name, curve in tmpl['curves'].items():
        ax.plot([t for t, _ in curve], [g for _, g in curve], label=name, color=colors.get(name, ink), lw=2)
    ax.set(xlabel='Seuil de distance cosinus', ylabel='GA (réglage, 1ʳᵉ moitié)', ylim=(0, 1.02),
           title='Regroupement des messages selon le seuil')
    ax.legend(fontsize=7.5, frameon=False)
    fig.tight_layout()
    fig.savefig(out / 's6_templates.png', dpi=160)
    plt.close(fig)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--raw', type=Path, default=ROOT / 'datasets/raw')
    ap.add_argument('--out', type=Path, default=ROOT / 'docs/experiments')
    ap.add_argument('--minilm', default=os.getenv('MINILM_DIR'))
    a = ap.parse_args(argv)
    fetch(a.raw)
    import s6_anomaly
    import s6_templates
    anom = s6_anomaly.run(a.raw / 'OpenSSH_2k.log')
    tmpl = s6_templates.run(a.raw / 'OpenSSH_2k.log_structured.csv', a.minilm)
    a.out.mkdir(parents=True, exist_ok=True)
    figures(anom, tmpl, a.out)
    slim = {'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'anomaly': {k: v for k, v in anom.items() if k not in ('pr_curve', 'scores')},
            'templates': {k: v for k, v in tmpl.items() if k != 'curves'}}
    (a.out / 's6_results.json').write_text(json.dumps(slim, ensure_ascii=False, indent=2, default=float), encoding='utf-8')
    for key in ('rules', 'isolation_forest', 'hybrid'):
        r = anom[key]
        print(f"{key:17s} F1={r['f1']:.3f} P={r['precision']:.3f} R={r['recall']:.3f} "
              f"IP attaquantes {r['attack_ips_found']}/{r['attack_ips']}, IP légitimes signalées {r['benign_ips_flagged']}/{r['benign_ips']}")
    for r in tmpl['results']:
        print(f"{r['method']:20s} GA={r['ga']:.3f} ARI={r['ari']:.3f} NMI={r['nmi']:.3f} groupes={r['clusters']} ({r['seconds']} s)")
    print('novelty', tmpl['novelty'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
