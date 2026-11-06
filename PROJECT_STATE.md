# PROJECT_STATE — CampusGuard / Sentinel

**Date de situation :** 6 novembre 2026. **Branche de travail :** `feat/s2-auth-upload-search` (la tranche CORE du 31 octobre est fusionnée dans `main`, PR #1). **Encadrant :** Mohamed Najeh Issaoui.

## Tranche S2 — authentification, upload, ingestion, recherche (6 novembre 2026)

**Statut honnête : IMPLÉMENTÉE et TESTÉE avec des services simulés ; NON ENCORE EXÉCUTÉE sur la stack Docker réelle.**

Ce qui est fait (code dans `app/`, `ingestion/logstash/pipeline/upload.conf`, `docker-compose.yml`) :

- **Authentification** : comptes MongoDB (`users`), mots de passe hachés (werkzeug), rôles Administrateur / Analyste SOC / Auditeur, sessions **côté serveur dans Redis** (`sentinel:session:*`, TTL, id régénéré à la connexion), CSRF, limitation des tentatives (5 échecs / 5 min par IP et par compte, compteurs Redis), audit MongoDB (`audit_actions`, sans mot de passe), en-têtes de sécurité dont CSP stricte. Comptes créés par `flask --app app.main seed-users`.
- **Upload CSV / JSON / JSONL / NDJSON / TXT / LOG** : limite de taille (10 Mo configurable), extension + type MIME + contrôle binaire/UTF-8, SHA-256 et refus des doublons, validation ligne par ligne (horodatage, IP, port, niveau, résultat), **aperçu des 10 premières lignes**, rapport d'erreurs avec numéro de ligne, rejet du fichier si trop de lignes invalides, confirmation avant ingestion.
- **Ingestion** : l'application écrit un NDJSON normalisé dans un volume partagé ; le pipeline Logstash `upload-security` le lit, revalide, enrichit (GeoIP, `event.ingested`), dédoublonne (id = upload + ligne) et indexe dans `logs-upload-*`. Les rejets vont dans `datasets/rejected/upload-<id>.ndjson`.
- **Statut mesuré** : reçu → validé → ingestion → **indexé / partiel / échec**, calculé à partir du comptage Elasticsearch (`labels.upload_id`) et du fichier de rejets — jamais déduit du HTTP 200 de l'upload.
- **Recherche** : texte libre, période UTC, niveau, service, résultat, IP/CIDR, utilisateur, import ; pagination (50 par page, limite 10 000), tri, détail d'un événement, **export CSV** (protégé contre l'injection de formules, plafonné et signalé), historique des 5 dernières recherches (MongoDB), cache Redis 30 s signalé dans la réponse.
- **Interface** (Jinja2 + CSS issue des maquettes, JS sans innerHTML) : connexion, tableau de bord applicatif (4 indicateurs et 3 graphiques Chart.js calculés par agrégations Elasticsearch, jamais de chiffres inventés), envoi de fichiers (choix du type CSV/JSON/TXT, contrôle de cohérence), explorateur avec tri par colonne, détail d'un événement ; thème clair/sombre.
- **API REST + Swagger** (module intermédiaire) : spécification OpenAPI 3.0.3 (`/api/openapi.json`) rendue par Swagger UI embarqué (`/api/docs`), alias stables `/api/v1/logs`, `/api/v1/logs/{id}`, `/api/v1/files`, `/api/v1/stats`, limitation de débit Redis (300 requêtes/min/utilisateur, HTTP 429 + `Retry-After`). Un test compare la spécification à la table de routage Flask. Voir `docs/API.md`.

Preuves **réelles** disponibles :

- `python -m pytest -q` → **166 passed** (21 tests S1 + 145 tests S2 : parsing 46, auth 19, upload 24, recherche 39, API/OpenAPI/débit 7, câblage Docker/Logstash/ES 10). MongoDB, Redis et Elasticsearch y sont **simulés** (mongomock, fakeredis, faux client ES) ; Logstash et Docker n'y sont pas exécutés.
- Parcours navigateur (Chromium) sur données simulées : connexion → upload → aperçu → confirmation → statut « Indexé » → recherche → détail, **0 erreur console** (CSP respectée) ; Swagger UI chargé sous la même CSP (17 opérations affichées).

**À exécuter par Syrine (non fait ici, car ni Docker ni Logstash n'existent dans l'environnement de développement)** :

```powershell
docker compose up -d --build --wait --wait-timeout 600
docker compose exec webapp flask --app app.main seed-users
python scripts/verify_s2.py --base-url http://127.0.0.1:8000 --username analyste --password "<mot de passe affiché>" --evidence docs/evidence/s2-verify-result.json
```

Tant que ce script n'a pas affiché 18/18 contrôles réussis, l'ingestion Logstash des uploads et le statut « indexé » sont considérés **non vérifiés**. Après un changement de template, relancer `docker compose up -d` (le conteneur `elasticsearch-init` réapplique le template ; les nouveaux champs concernent les nouveaux index `logs-upload-*`).

Écarts et limites assumés :

- La normalisation (horodatage UTC, IP, niveaux) est faite par l'application (`app/services/parsing.py`, testée) ; Logstash est la seconde validation et l'indexeur. Les horodatages sans fuseau sont **supposés UTC** et signalés ; une ligne TXT sans horodatage reçoit l'heure de réception (`labels.time_mode = ingest`).
- Les motifs `sshd` du parseur TXT sont heuristiques et **non validés** sur le corpus OpenSSH complet.
- Le nouvel index suit le schéma `dynamic: false` : seuls les champs mappés sont filtrables.
- Pas encore : visualisations Kibana (3 exigées) et dashboard Kibana exporté avec intégration dans l'application (S3), alertes G, temps réel H, gestion des utilisateurs par l'interface, validation des motifs OpenSSH sur un vrai corpus.

## Résultat de la tranche CORE (31 octobre 2026)

**PASS — infrastructure CORE fonctionnelle et démontrée localement.**

- Docker 28.4 et Docker Compose 2.39.4.
- Elasticsearch, Logstash et Kibana 8.19.10 ; MongoDB 7.0 ; Redis 7.4.
- Elasticsearch, MongoDB, Redis, Logstash, Kibana et Flask sont `healthy` ; `elasticsearch-init` et `kibana-init` se terminent avec `Exited (0)`.
- `GET /ready` répond HTTP 200 avec Elasticsearch, MongoDB et Redis à `ok`. La disponibilité Elasticsearch exige un statut de cluster `yellow` ou `green` et `timed_out: false` ; un cluster rouge ou expiré rend l’endpoint dégradé.
- `scripts/verify_core.py` : **8/8 contrôles PASS**.
- Elasticsearch : **100 documents** dans `logs-auth-*` et **100 documents** dans `logs-firewall-*`.
- Template Elasticsearch : l’API confirme `dynamic: false`. `setup-index.sh` applique aussi ce réglage aux indices `logs-*` déjà existants. Un champ inconnu reste visible dans `_source`, mais n’est pas indexé et ne peut pas être recherché comme champ.
- Kibana : data view `logs-*` présente ; 200 documents consultables dans Discover.
- JSON invalide : l’entrée HTTP Logstash répond 200, puis le pipeline place l’événement dans `datasets/rejected/json-dead-letter.jsonl` avec les tags `_jsonparsefailure`, `_missing_timestamp`, `_missing_source_ip` et `_missing_event_outcome`.
- Types JSON invalides : les probes avec `message` objet, `labels` chaîne, `source.geo` chaîne ou `threat` chaîne reçoivent HTTP 200 à l’entrée, puis `_invalid_field_type`, sont écrites en dead-letter et produisent chacune 0 document Elasticsearch. Toute exception du filtre Ruby est également routée vers le rejet.
- Tests CORE du 31 octobre : `python -m pytest -q` → **21 passed** (depuis S2 : 166, voir ci-dessus).
- `docker compose config -q` et `docker compose --profile stream config -q` → PASS. Le profil STREAM a uniquement été validé syntaxiquement ; il n’a pas été lancé.

Preuves à inclure au même commit : [validation détaillée](docs/evidence/CORE_VALIDATION_2026-10-31.md) et [capture Kibana Discover](docs/evidence/core-kibana-discover.png). Aucun lien ne dépend des rapports locaux générés dans `reports/`.

## Particularité du port Elasticsearch

Le port hôte par défaut reste `127.0.0.1:9200` et peut être remplacé par `ELASTICSEARCH_PORT`. La validation a utilisé `127.0.0.1:9201`, car une instance Elasticsearch WSL 8.19.23 sécurisée occupait déjà 9200. Les communications internes Docker restent sur `http://elasticsearch:9200`.

## Mesure mémoire finale

| Service | Mémoire mesurée |
|---|---:|
| Elasticsearch | 1018 MiB |
| Kibana | 548,5 MiB |
| Logstash | 565,9 MiB |
| MongoDB | 63,56 MiB |
| Redis | 8,188 MiB |
| Flask | 58,02 MiB |
| **Total CORE approximatif** | **2262 MiB, soit 2,21 GiB** |

Mémoire physique de l’hôte : 13,88 GiB au total, 89,0 % utilisés et 1,53 GiB disponibles au moment de la mesure. **Kafka ne doit pas être lancé dans cet état.** Une nouvelle mesure et une marge mémoire suffisante sont requises avant tout essai STREAM.

## Sécurité et persistance

- Tous les ports de développement sont liés à `127.0.0.1`.
- `xpack.security.enabled=false` est accepté uniquement pour ce laboratoire local isolé ; cette configuration n’est pas adaptée à la production ni à une exposition réseau.
- Les positions Logstash sont persistées dans le volume `logstash-data`, sous `/usr/share/logstash/data`, et non dans `/tmp`.
- Les entrées fichier utilisent `file_completed_action => "log"` : leur achèvement est journalisé et les sources `auth.jsonl` et `firewall.csv` restent présentes après ingestion.
- L’arrêt normal est `docker compose down` sans `-v`, afin de conserver les volumes.

## Non réalisé ou non validé

- Authentification, upload, recherche : **développés en S2 (voir plus haut), non validés sur la stack Docker réelle**.
- Trois visualisations de sécurité et dashboard Kibana exporté : non réalisés ; seule la data view et Discover sont validés.
- Alerting G, blocage TTL, temps réel H, Kafka, ML et NLP : non développés ou non exécutés.
- Source historique OpenSSH complète : non intégrée et non comptée.
- Installation sur une seconde machine : non testée.

## Git et coordination externe

- Le dépôt distant existe : <https://github.com/syrinemrf/CampusGuard>.
- La tranche CORE a été publiée sur `feat/core-infrastructure` et **fusionnée dans `main`** via la [Pull Request #1](https://github.com/syrinemrf/CampusGuard/pull/1) ; le contrôle GitGuardian était réussi. La tranche S2 est sur `feat/s2-auth-upload-search` (pas encore poussée tant que Syrine n'a pas validé).
- Les preuves et le lien de PR ont été ajoutés aux tickets Jira `KAN-13`, `KAN-14`, `KAN-16`, `KAN-17` et `KAN-18`, sans changement de statut.
- Le suivi reste en Kanban avec WIP maximal de 2 ; aucune tâche ne doit être clôturée sans preuve réelle.

## Prochaine tranche

1. **Valider S2 sur la stack réelle** (`scripts/verify_s2.py`, 18 contrôles) et ajouter la sortie comme preuve dans `docs/evidence/`.
2. Fermer les écarts S1 encore non prouvés : source OpenSSH réelle (parseur + comptes), mesure mémoire avec webapp S2, accès de l'encadrant à Jira, unification des 10 vues Figma.
3. S3 : dashboard (KPI, séries temporelles), trois visualisations Kibana + dashboard exporté, gestion des utilisateurs, couverture de tests ≥ 70 %, tag `v1.0-mvp` après test.
Kafka, ML et NLP restent hors périmètre tant que le MVP obligatoire n'est pas couvert.
