# CampusGuard — ordre d'exécution accéléré

**Règle :** un livrable *end-to-end* et testé vaut mieux que plusieurs composants incomplets. Travail en Kanban WIP ≤2, compte-rendu après chaque tranche. N'appeler une tâche « terminée » qu'avec une preuve réelle.

| Gate | Tickets Jira | Travail autonome Codex | Définition de terminé |
|---|---|---|---|
| A — Boot CORE | KAN-13,14,16,18 | Examiner Compose/ports/santé, lancer ES/Mongo/Redis/Logstash/Kibana/Flask, corriger | `docker compose ps` healthy ; `curl /ready` 200 ; >=1 événement indexé ; capture Discover ; mesure RAM |
| B — Données | KAN-15,16 | OpenSSH, parser, anonymiser, échantillonner, sources synthétiques CSV/JSON | provenance et compteurs documentés ; indexation réelle ; rejets distincts et testés |
| C — Upload | KAN-39,40,41 | Auth/session + Jinja/Bootstrap upload, taille/format/MIME, 10 lignes, Mongo et statut | CSV/JSON/TXT valides indexés ; invalides rejetés avec raison ; tests API/UI |
| D — Recherche | KAN-42 et S3 | ES Query DSL, filtres, pagination 50, tri/détail/export, recherches Mongo | Recherche retourne événements importés ; export filtré identique ; tests |
| E — UI/Kibana MVP | KAN-21 & tâches S3 | Reproduire HTML dans Jinja + Chart.js, 3 visuels Kibana, un dashboard exporté | 5 pages principales et responsive ; dashboard fonctionnel ; tag `v1.0-mvp` après test |
| F — Avancé G | KAN-22 & tâches S4 | Règles, worker, alertes, ack/resolve/snooze, notifications, TTL blocklist locale | Une séquence 5 échecs/5 min déclenche alerte auditable + blocage réversible |
| G — Avancé H | KAN-23 & tâches S5 | Streaming avec TCP/HTTP/Filebeat, UI live SSE/WebSocket, indicateurs et reprise | live-tail avec pause/reconnexion et mesure de latence ; Kafka UNIQUEMENT si budget RAM |
| H — Durcissement | KAN-24,25 | pytest, CI, charge, sécurité, docs, vidéo, rapport, répétition | PR propres, tests verts, installation documentée, livrables complets |

## Démarrage conseillé (WSL2 Ubuntu + Docker Desktop)

```bash
git clone https://github.com/syrinemrf/CampusGuard.git
cd CampusGuard
cp .env.example .env
python3 simulator/generate.py
mkdir -p datasets/rejected
docker compose config -q
docker compose up -d --wait elasticsearch mongodb redis
bash scripts/setup-index.sh
docker compose up -d --build logstash kibana webapp
docker compose ps
curl -fsS http://localhost:8000/ready
curl -fsS 'http://localhost:9200/_cat/indices/logs-*?v'
docker stats --no-stream
```

Codex doit **vérifier les commandes contre le code réel et corriger les échecs** avant d'affirmer qu'elles ont réussi. Ne pas démarrer le profil `stream` avant que le MVP soit stable.

## Sortie attendue de chaque tâche Codex
- `Résultat` : PASS / FAIL / NON TESTÉ ; captures et métriques réelles.
- `Code` : fichiers touchés, tests effectués, commit ou PR.
- `Jira` : tickets actualisés si accès, sinon contenu prêt à coller.
- `Risques` : anomalies ouvertes, dépendances matérielles.
- `Suite` : une prochaine tranche bien circonscrite, pas une refonte globale.
