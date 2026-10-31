# Validation CORE — 31 octobre 2026

## Périmètre

Cette preuve couvre la branche `feat/core-infrastructure` et le parcours CORE suivant :

```text
échantillons JSONL/CSV → Logstash → Elasticsearch → Kibana Discover
                                  ↘ Flask /ready → Elasticsearch, MongoDB, Redis
```

Elle ne valide ni le profil STREAM ni le MVP web complet.

## Environnement réellement utilisé

| Composant | Version ou état |
|---|---|
| Docker | 28.4 |
| Docker Compose | 2.39.4 |
| Elasticsearch / Logstash / Kibana | 8.19.10 |
| MongoDB | 7.0 |
| Redis | 7.4 |
| Branche | `feat/core-infrastructure` |
| Date de validation | 31 octobre 2026 |

Le port hôte Elasticsearch est `9200` par défaut via `ELASTICSEARCH_PORT`. Pour cette validation, il a été remplacé par `9201`, car Elasticsearch WSL 8.19.23 sécurisé occupait déjà `9200`. Ce changement concerne seulement la publication sur l’hôte ; les conteneurs communiquent toujours avec `http://elasticsearch:9200`.

## Procédure CORE

Commandes de démarrage utilisées, depuis la racine du dépôt :

```powershell
$env:ELASTICSEARCH_PORT = "9201"
python simulator/generate.py
docker compose config -q
docker compose up -d --build --wait --wait-timeout 600
```

Vérifications :

```powershell
python scripts/verify_core.py `
  --elasticsearch-url http://127.0.0.1:9201 `
  --wait-timeout 300
python -m pytest -q
.\scripts\feasibility.ps1
docker compose --profile stream config -q
```

Arrêt conservant les données et positions de lecture :

```powershell
docker compose down
```

`docker compose down -v` n’est pas utilisé : l’option supprimerait les volumes persistants Elasticsearch, MongoDB, Redis et Logstash.

## Résultats

### Services et dépendances

- Elasticsearch : `healthy`.
- MongoDB : `healthy`.
- Redis : `healthy`.
- Logstash : `healthy`, avec les pipelines `csv-security` et `json-security` disponibles.
- Kibana : `healthy`.
- Flask/Gunicorn : `healthy`.
- `elasticsearch-init` : `Exited (0)` après installation du template.
- `kibana-init` : `Exited (0)` après création de la data view.
- `GET http://127.0.0.1:8000/ready` : HTTP 200, avec Elasticsearch, MongoDB et Redis à `ok`. Le contrôle Elasticsearch accepte uniquement les états de cluster `yellow` ou `green` avec `timed_out: false` ; une réponse rouge ou expirée produit un état dégradé.

### Vérificateur reproductible

`scripts/verify_core.py` a retourné **8/8 PASS** :

1. disponibilité Flask `/ready` ;
2. présence du template Elasticsearch `campusguard-logs` ;
3. minimum documentaire pour `logs-auth-*` ;
4. minimum documentaire pour `logs-firewall-*` ;
5. champs ECS attendus sur un événement d’authentification ;
6. champs ECS attendus sur un événement pare-feu ;
7. disponibilité Kibana ;
8. présence de la data view `logs-*`.

### Ingestion et consultation

| Contrôle | Résultat |
|---|---:|
| `logs-auth-*` | 100 documents |
| `logs-firewall-*` | 100 documents |
| Total visible dans Discover | 200 documents |
| Data view | `logs-*` |

La data view apparaît dans l’interface sous le nom « CampusGuard logs ». La capture montre les champs normalisés `@timestamp`, `service.name`, `event.action`, `event.outcome`, `source.ip`, `log.level` et `message` : [ouvrir la capture Kibana Discover](core-kibana-discover.png).

L’API Elasticsearch a confirmé `dynamic: false` sur le mapping du template `campusguard-logs`. Lors de l’installation, `setup-index.sh` applique également `dynamic: false` aux mappings des indices `logs-*` déjà existants. Les champs inconnus sont conservés dans `_source` pour consultation du document brut, mais ils ne sont pas ajoutés dynamiquement au mapping : ils ne sont donc ni indexés ni recherchables comme champs.

### Identité documentaire et nettoyage des probes

Deux événements de test identiques à l’exception de `user.name` ont produit deux documents Elasticsearch distincts. Le fingerprint SHA-256 du pipeline inclut notamment `user.name` et `service.name`, en plus des autres champs d’identité de l’événement.

Le nettoyage ciblé a ensuite supprimé exactement les deux documents de probe. La recherche de contrôle a retourné 0 probe restante et le compteur `logs-auth-*` est revenu à 100 documents ; les compteurs du tableau ci-dessus excluent donc ces événements de validation temporaires.

### Cas invalides

#### JSON syntaxiquement invalide

Un corps JSON volontairement invalide (`{invalid-json`) a été envoyé à l’entrée HTTP Logstash sur `127.0.0.1:8088`. L’entrée a répondu HTTP 200, ce qui signifie uniquement que Logstash a accepté la requête. Le pipeline a ensuite refusé l’événement pour l’indexation normale et l’a écrit dans `datasets/rejected/json-dead-letter.jsonl`.

Tags observés :

```text
_jsonparsefailure
_missing_timestamp
_missing_source_ip
_missing_event_outcome
```

Ce test démontre la séparation entre acceptation HTTP et validation métier du pipeline.

#### Types de champs invalides

Quatre événements JSON syntaxiquement valides ont été envoyés séparément à la même entrée HTTP avec, respectivement, `message` sous forme d’objet, `labels` sous forme de chaîne, `source.geo` sous forme de chaîne et `threat` sous forme de chaîne. Pour chacun, les résultats observés sont :

- réponse HTTP 200 de l’entrée Logstash ;
- ajout du tag `_invalid_field_type` ;
- écriture dans `datasets/rejected/json-dead-letter.jsonl` ;
- **0 document correspondant dans Elasticsearch**.

Ce contrôle vérifie qu’un événement accepté par le transport n’est pas indexé lorsque le type d’un champ métier est incompatible avec le mapping attendu.

Le filtre Ruby utilise aussi un tag d’exception dirigé vers cette même branche de dead-letter ; la condition de sortie couvre également `_rubyexception`. Ainsi, une exception Ruby ne contourne pas le rejet pour atteindre Elasticsearch.

### Tests et configurations

| Commande | Résultat |
|---|---|
| `python -m pytest -q` | 21 passed |
| `docker compose config -q` | PASS |
| `docker compose --profile stream config -q` | PASS, configuration seulement |

Le profil STREAM et Kafka n’ont pas été démarrés.

## Consommation mémoire

Mesure finale de `docker stats --no-stream`, limitée aux conteneurs CampusGuard :

| Service | Utilisation | Limite Compose |
|---|---:|---:|
| Elasticsearch | 1018 MiB | 1,5 GiB |
| Kibana | 548,5 MiB | 768 MiB |
| Logstash | 565,9 MiB | 768 MiB |
| MongoDB | 63,56 MiB | 384 MiB |
| Redis | 8,188 MiB | 192 MiB |
| Flask | 58,02 MiB | 256 MiB |
| **Total approximatif** | **2262 MiB / 2,21 GiB** | — |

État de l’hôte Windows au même moment :

- mémoire visible : 13,88 GiB ;
- utilisation : 89,0 % ;
- mémoire disponible : 1,53 GiB.

Verdict : CORE tient dans ses limites de conteneurs, mais la marge globale de l’hôte est insuffisante pour autoriser Kafka. Une nouvelle mesure, dans un environnement libérant davantage de RAM, est obligatoire avant tout démarrage STREAM.

## Persistance et redémarrage

Les fichiers `auth.sincedb` et `firewall.sincedb` sont enregistrés dans `/usr/share/logstash/data`, monté sur le volume nommé `logstash-data`. Ils ne résident pas dans `/tmp`. Une simple recréation du conteneur ne rejoue donc pas automatiquement les mêmes fichiers.

Les deux entrées fichier Logstash sont configurées avec `mode => "read"` et `file_completed_action => "log"`. À la fin de la lecture, Logstash écrit le chemin traité dans `auth-completed.log` ou `firewall-completed.log` ; cette action ne supprime pas les fichiers source `datasets/samples/auth.jsonl` et `datasets/samples/firewall.csv`.

Cette preuve Markdown et la capture Kibana liée sont destinées au versionnement. Aucun lien de cette page ne pointe vers les rapports d’exécution locaux créés dans `reports/`.

## Limites de cette preuve

- Pas d’authentification ni de rôles.
- Pas d’upload Flask CSV/JSON/TXT, de prévisualisation ou de suivi MongoDB.
- Pas de recherche applicative ni d’export CSV.
- Pas encore de trois visualisations métier ni de dashboard Kibana exporté.
- Pas d’alerting, de blocage TTL, de flux live, de Kafka, de ML ou de NLP.
- Pas de test sur une seconde machine.

Enfin, Elasticsearch fonctionne avec `xpack.security.enabled=false`. Tous les ports sont liés à `127.0.0.1` et cette exception est acceptable uniquement pour le laboratoire de développement local isolé ; elle ne doit jamais être exposée sur un réseau public.
