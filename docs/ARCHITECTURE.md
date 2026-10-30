# Architecture globale — CampusGuard / Sentinel (S1)

## Source de vérité et périmètre

Architecture cible inspirée du schéma fourni `sentinel_architecture_globale_v2.png` : Security Data Sources → ingestion shipper (sources directes, Filebeat, TCP/HTTP) → Kafka → indexer → Elasticsearch/Kibana ; Redis + MongoDB servent respectivement à l'état rapide et aux données métier ; Flask accueille les vues et le middleware de laboratoire ; workers de détection/SOAR en phases futures. **S1 : CORE sans Kafka sur le trajet de données ; STREAM est un squelette expérimental.**

## 1. C4 niveau 1 — Contexte

```mermaid
flowchart LR
Analyst[Analyste SOC] --> App[CampusGuard / Sentinel]
Admin[Administrateur] --> App
Auditor[Auditeur] --> App
Sources[Logs OpenSSH / Simulateur / Cowrie optionnel] --> App
App --> E[Elasticsearch & Kibana]
App --> M[MongoDB]
App --> R[Redis]
```

## 2. C4 niveau 2 — Conteneurs

```mermaid
flowchart LR
subgraph Sources
S1[OpenSSH historique]
S2[Simulateur normal / attaque]
S3[Cowrie isolé facultatif]
end
subgraph Core
LS[Logstash CORE CSV / JSON / TCP / HTTP / Beats]
ES[(Elasticsearch 8.x)]
KB[Kibana]
Web[Flask / gunicorn]
MG[(MongoDB)]
RD[(Redis)]
end
S1 --> LS
S2 --> LS
S3 -.via Filebeat, VPN ou SSH read-only.-> LS
LS --> ES
ES --> KB
Web --> ES
Web --> MG
Web --> RD
subgraph Stream [S3 — Architecture cible facultative]
SH[Logstash shipper]
KA[(Kafka KRaft)]
IN[Logstash indexer]
DT[Détecteur consommateur]
SH --> KA --> IN
KA --> DT
end
IN -.-> ES
DT -.-> MG
DT -.-> RD
```

## 3. Flux temps réel cible et responsabilités

- ES = documents d'événements, recherche, agrégations, historique analytique.
- MongoDB = utilisateurs, fichiers, alertes, incidents, requêtes sauvegardées, audit, tableaux personnalisés. Stocker références vers IDs ES, pas duplicata intégral des logs.
- Redis = cache ES, sessions, tokens de rate-limiting, compteurs fenêtre, blocklist TTL, événements légers et bus de repli. Redis Pub/Sub seul n'est pas durable ; l'adaptateur Redis utilise aussi Streams pour limiter les pertes et le documente explicitement.
- Kafka = tampon/rejeu, topics métiers, ordre par clé IP à l'intérieur d'une partition, consommateurs indépendants ; désactivé dans CORE. 24 h rétention initiale ; latence à mesurer.

## 4. C4 niveau 3 — modules Flask cibles

```mermaid
flowchart TB
Entry[Routes HTML + API REST] --> Search[Recherche / export]
Entry --> Upload[Upload validation]
Entry --> Incident[Alertes & incidents]
Entry --> Auth[Authentification RBAC]
Search --> ES[ES client]
Upload --> Files[FileService + métadonnées Mongo]
Incident --> Work[RuleService / audit Mongo / Redis TTL]
Auth --> Mongo[MongoDB]
Entry --> Bus[EventBus interface]
Bus --> K[KafkaBus]
Bus --> R[RedisBus]
```

S1 fournit `Flask /health /ready` et interface EventBus, pas les modules ci-dessus en production.

## 5. Modèle Elasticsearch et conventions

Index `logs-*`, 1 shard, 0 replica en laboratoire single-node. Champs pivots : `@timestamp:date`, `event.category/action/outcome:keyword`, `user.name:keyword`, `source.ip:ip`, `source.geo.location:geo_point`, `source.geo.country_iso_code:keyword`, `service.name:keyword`, `log.level:keyword`, `message:text`, `labels.ground_truth:keyword`, `threat.technique.id:keyword`. Ajouter `event.ingested:date` par pipeline (S2). **Le template est dans `ingestion/elasticsearch/logs-template.json`.** Tous les horaires source seront normalisés en UTC ; utiliser l'heure d'ingestion en fallback seulement si un champ de qualité signale l'absence d'heure source.

## 6. Modèles MongoDB — collections et champs

| Collection | Champs structurants | Index à prévoir |
|---|---|---|
| users | `_id`, username, password_hash, role, active, created_at | username unique |
| uploaded_files | `_id`, original_name, sha256, source_type, size_bytes, uploaded_by, state, indexed_count, errors, created_at | (uploaded_by, created_at), sha256 |
| saved_searches | `_id`, user_id, text, filters, created_at | (user_id, created_at) |
| dashboards | `_id`, owner_id, name, layout, widget_configs, visibility, updated_at | owner_id |
| alerts | `_id`, fingerprint, rule_id, ip, user_id, risk_score, status, severity, mitre_ids, created_at, resolved_at | fingerprint, created_at, status |
| incidents | `_id`, alert_ids, assignee, timeline, status, mttr_seconds | status, assignee |
| audit_actions | `_id`, actor_id, action, target, reason, timestamp, before, after | (actor_id,timestamp) |

Les champs de données personnelles sensibles ne doivent pas être copiés sans nécessité.

## 7. Redis — keyspaces et TTL indicatifs

- `sentinel:auth:fail:{ip}` sorted set, fenêtre 300s ; `sentinel:blocked:{ip}` clé TTL 3600s ; `sentinel:cache:search:{sha256}` TTL 60s ; `sentinel:reputation:{ip}` TTL 86400s ; `sentinel:session:{id}` TTL configurable ; `sentinel:logs.auth` Redis Stream borné ; `sentinel:live:alerts` canal Pub/Sub.
- En S1, seule la façade `RedisBus` et ses tests unitaires sont fournis.

## 8. Séquences

### Importation / recherche (S2)
```mermaid
sequenceDiagram
  actor Analyst
  participant Web as Flask
  participant Mongo
  participant LS as Logstash
  participant ES
  Analyst->>Web: Upload CSV/JSON/TXT
  Web->>Web: validate, preview, sha256, limit
  Web->>Mongo: save uploaded_files state=pending
  Web->>LS: place file in watch directory
  LS->>ES: normalize + bulk index
  Web->>ES: query indexed_count
  Web->>Mongo: state=indexed/failed
  Web-->>Analyst: status + search link
```

### Détection et blocage labo (S4–S5)
```mermaid
sequenceDiagram
  participant ES
  participant Worker as Detector
  participant Redis
  participant Mongo
  participant Web
  Worker->>ES: new auth failures per source.ip
  Worker->>Redis: update rolling window 5 min
  alt 5 fails in 5 min
    Worker->>Redis: SET blocked:ip EX 3600
    Worker->>Mongo: insert alert + audit
    Worker-->>Web: publish live alert
    Web-->>Web: deny ONLY lab service traffic
  end
```

### Streaming cible (S3+)
```mermaid
sequenceDiagram
  participant Source
  participant Ship as Logstash shipper
  participant Kafka
  participant Indexer as Logstash indexer
  participant Detector
  participant ES
  Source->>Ship: TCP/HTTP/Beats event
  Ship->>Kafka: keyed normalized event
  par independent consumers
    Kafka->>Indexer: consumer group logstash-indexer
    Indexer->>ES: index event
  and
    Kafka->>Detector: group sentinel-detector
  end
```

## 9. Déploiement, sécurité et supervision

`docker-compose.yml` définit un pont `sentinel`, volumes pour ES/Mongo/Redis, limites RAM et healthchecks. Ports de labo liés à `127.0.0.1` ; ES 8.x sécurité volontairement désactivée dans DEV : **ne jamais utiliser cette configuration en production ou la rendre accessible sur Internet.** Kafka en profil `stream`. Cowrie sur un VPS séparé si disponible, pas sur le LAN de l'école. Les authentifications et sessions arriveront S2. `docker stats` + `/ready` + `/_cluster/health` sont les probes S1 ; logs JSON applicatifs structurés et CI arriveront ensuite.

## 10. Hypothèses et écarts documentés

La documentation du prompt cite 655k lignes OpenSSH, nombre à confirmer sur le corpus téléchargé. Le schéma fourni présente un flux Kafka ; son rôle dans CORE est délibérément repoussé pour la mémoire locale. Le chemin Kafka–indexer–détecteur n'est pas câblé en S1. L'ingestion de vrais logs OpenSSH nécessite un parseur grok spécifique après inspection d'un extrait réel ; elle ne doit **pas** être considérée opérationnelle à ce stade. La conformité de chaque conteneur doit être vérifiée par lancement Docker réel.
