# PROJECT_STATE — CampusGuard / Sentinel

**Date de situation :** 31 octobre 2026. **Branche de travail :** `feat/core-infrastructure`. **Encadrant :** Mohamed Najeh Issaoui.

## Résultat de la tranche CORE

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
- Tests : `python -m pytest -q` → **21 passed**.
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

- Authentification et rôles : non développés.
- Upload CSV/JSON/TXT via Flask, aperçu et métadonnées MongoDB : non développés.
- Recherche applicative, pagination, détail et export CSV : non développés.
- Trois visualisations de sécurité et dashboard Kibana exporté : non réalisés ; seule la data view et Discover sont validés.
- Alerting G, blocage TTL, temps réel H, Kafka, ML et NLP : non développés ou non exécutés.
- Source historique OpenSSH complète : non intégrée et non comptée.
- Installation sur une seconde machine : non testée.

## Git et coordination externe

- Le dépôt distant existe : <https://github.com/syrinemrf/CampusGuard>.
- Le travail est publié sur `feat/core-infrastructure` dans la [Pull Request #1](https://github.com/syrinemrf/CampusGuard/pull/1), ouverte vers `main` ; le contrôle GitGuardian est réussi.
- Les preuves et le lien de PR ont été ajoutés aux tickets Jira `KAN-13`, `KAN-14`, `KAN-16`, `KAN-17` et `KAN-18`, sans changement de statut.
- Le suivi reste en Kanban avec WIP maximal de 2 ; aucune tâche ne doit être clôturée sans preuve réelle.

## Prochaine tranche

Développer verticalement l’authentification/session et l’upload validé CSV/JSON/TXT, avec aperçu, métadonnées MongoDB, statuts, rejets et test d’intégration jusqu’à Elasticsearch. Kafka, ML et NLP restent hors périmètre tant que le MVP obligatoire n’est pas couvert.
