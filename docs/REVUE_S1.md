# Revue S1 — 30 octobre 2026

## Livrables produits

Analyse fonctionnelle, architecture C4 (Mermaid), trois séquences, stratégie CORE/STREAM, deux ADR, user journey, six écrans desktop et deux variantes mobiles éditables Figma, modèles ES/Mongo/Redis, configuration Docker Compose avec healthchecks et ressources, bootstrap index, deux pipelines, backend Flask minimal, simulateur de journaux, deux bus prototypes et suite de tests.

## Résultats effectivement démontrés dans le contexte de création

- **PASS** : parsing YAML du Compose, 8 services, deux services avec profil `stream`, limites mémoire sur les 8 services, 7 healthchecks.
- **PASS** : analyse syntaxique du code Python et structure du mapping Elasticsearch (champs `source.ip` et `source.geo.location`).
- **PASS** : simulateur : 100 logs auth JSONL + 100 logs firewall CSV, labels simulés `normal`/`attack`.
- **NON EXÉCUTÉ** : tests `pytest` (packages Flask/PyMongo/Redis indisponibles, accès réseau PyPI impossible dans cet environnement).
- **NON EXÉCUTÉ** : tests Docker Compose, démarrage Elasticsearch/Logstash/Kibana, mesure de RAM et vérification Discover (Docker absent).
- **NON EXÉCUTÉ** : ingestion Loghub OpenSSH (aucun corpus historique récupéré dans l'environnement ; téléchargement/parsing nécessaires).
- **NON EXÉCUTÉ** : invitation du professeur sur Jira (compte non retrouvé et action d'invitation indisponible dans le connecteur).
- **NON PUBLIÉ** : repository GitHub (le connecteur permet les opérations sur dépôts existants, pas la création d'un nouveau dépôt).

## Risques résiduels prioritaires

1. Exécuter `docker compose config` et démarrer CORE sur 12 Go RAM ; résoudre d'éventuels problèmes de tags Elastic, de santé et de ports.
2. Importer le corpus historique OpenSSH depuis sa source officielle, documenter licence, provenance, format et nombre de lignes ; développer le parsing adapté.
3. Tester les pipelines sur de vrais événements et relever les échecs de parsing.
4. Créer le dépôt GitHub et publier l'archive ; donner un accès de consultation/commentaire au professeur sur Jira.
5. Compléter les variantes mobile et interactions des maquettes.

**Conclusion : S1 livrables de conception et de code préparés, validation d'exécution locale non obtenue. Le jalon S1 ne peut être qualifié d'opérationnel tant que Docker/ELK et Loghub n'ont pas été réellement testés.**
