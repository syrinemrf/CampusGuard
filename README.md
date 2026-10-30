# CampusGuard / Sentinel

Mini-SIEM/SOAR explicable, **niveau S1 (fondations)**. ITBS — Syrine Maaref — encadrant : Mohamed Najeh Issaoui. Date cible : 12 décembre 2026.

> État vérifié : tests unitaires et validation statique effectués dans l'environnement de création. Le fonctionnement de Docker Compose/ELK sur le PC étudiant n'a **pas** encore été démontré. Les maquettes UX ne sont pas encore intégrées à Flask ; aucun moteur d'alerte, de ML ou de blocage n'est actif en S1.

## Prérequis

Docker Desktop / Docker Engine avec Compose v2, WSL2 Ubuntu si Windows, mémoire WSL2 allouée suffisante. Machine cible 12 Go RAM : fermer les applications gourmandes et **surveiller `docker stats`**. Les limites mémoire plafonnent les processus, elles ne garantissent pas que toute la stack est fluide. Les versions sont épinglées dans `.env.example` ; vérifier la disponibilité exacte des tags avant le premier démarrage.

## Démarrage CORE

```bash
cp .env.example .env
python3 simulator/generate.py
mkdir -p datasets/rejected
# Lancer les services persistants, puis initialiser le mapping AVANT Logstash
docker compose up -d elasticsearch mongodb redis
# attendre la santé Elasticsearch ; vérifier : curl -f http://localhost:9200
bash scripts/setup-index.sh
docker compose up -d --build logstash kibana webapp
docker compose ps
curl -f http://localhost:8000/health
curl -f http://localhost:8000/ready
curl -s 'http://localhost:9200/logs-*/_count?ignore_unavailable=true'
```

Kibana : `http://localhost:5601` ; Flask : `http://localhost:8000` ; Elasticsearch : `http://localhost:9200`.

Dans Kibana, créer une vue de données `logs-*` basée sur `@timestamp`. Première ingestion à vérifier dans Discover ; les visualisations finales sont planifiées S3. Une première initialisation Elasticsearch/Kibana peut prendre plusieurs minutes selon disque/RAM.

### Attention importante sur l'ordre d'ingestion

Les exemples sont écrits AVANT l'exécution de Logstash. Le pipeline CSV et JSON est en lecture de fichiers ; il faut les régénérer ou utiliser de nouveaux noms de fichiers si l'on souhaite reconsommer une seconde fois. Les chemins surveillés sont `datasets/samples/firewall.csv` et `datasets/samples/auth.jsonl`. Les parse failures sont envoyés dans `datasets/rejected` et doivent être contrôlés. L'index template doit être installé avant toute ingestion.

## Test de faisabilité mémoire (obligatoire)

```bash
bash scripts/feasibility.sh
# Profil streaming en seconde phase, seulement si CORE fonctionne
# docker compose --profile stream up -d kafka
# docker compose --profile stream ps
```

Comparer mémoire réellement utilisée / mémoire hôte disponible et vérifier les healthchecks. Si le cumul approche 80% de la RAM disponible, **désactiver le profil STREAM** et conserver le repli Redis jusqu'à optimisation. Les services Compose sans profil appartiennent à CORE. `BUS_BACKEND=redis` est le repli logique ; le code d'intégration de Kafka au pipeline n'est pas encore actif.

## Kafka STREAM (prototype S1, intégration prévue S3)

```bash
docker compose --profile stream up -d kafka
bash scripts/kafka-init-topics.sh
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list
docker compose exec kafka /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server kafka:9092 --list
```

Le listener interne `kafka:9092` est destiné aux conteneurs du réseau Docker ; le listener externe `localhost:29092` aux outils lancés sur le PC. **Ne pas** exposer `29092` à Internet. Aucun producteur/consommateur réel n'est branché en S1. Attention : le fichier Filebeat fourni nécessite l'activation de son service de profil et un fichier `stream-auth.jsonl`. Il reste à valider en conditions réelles.

## Exécuter les tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r app/requirements.txt pytest
python3 -m pytest -q
python3 -m compileall -q app bus simulator
python3 -m json.tool ingestion/elasticsearch/logs-template.json >/dev/null
```

## Sécurité

Environnement **local de laboratoire uniquement** : Elasticsearch sans sécurité, interfaces liées à `127.0.0.1`, données simulées avec plages IP de documentation RFC 5737. Aucun mot de passe réel ni accès SSH universitaire. Ne pas exposer les ports de développement publiquement. Le honeypot Cowrie n'est pas déployé ; un éventuel VPS devra être isolé et connecté uniquement par tunnel privé ou extraction SSH en lecture seule.

## Fin de session

```bash
docker compose down       # conserve les volumes
docker compose down -v    # destructif : supprime index / données persistées
```

## Livrables et état

- `docs/ANALYSE_FONCTIONNELLE.md` : besoins et matrice de conformité.
- `docs/ARCHITECTURE.md` : C4, flux, modèle de données, séquences et deployment.
- `docs/ADR/` : décisions structurantes.
- `docs/USER_JOURNEY.md` : parcours utilisateur, maquettes et critères UX.
- `PROJECT_STATE.md` : transparence sur le réel / le prévu.
- `scripts/` : bootstrap mappings, audit mémoire, init topics.

**S1 ne signifie pas MVP complet.** Auth, upload, recherche, incident, ML, alerting, WebSockets et dashboards Kibana définitifs sont planifiés S2–S6.
