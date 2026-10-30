# CampusGuard — PROJECT_STATE

Dernière mise à jour : 2026-10-30. **Ne jamais confondre fichier créé et service testé sur la machine cible.**

## Fait et vérifié dans l'environnement de création

- Analyse fonctionnelle, architecture C4/Mermaid, schémas ES/Mongo/Redis, ADR et user journey rédigés.
- Structure applicative Flask `/`, `/health`, `/ready`, tests unitaires de la logique de base.
- Compose avec ES, Mongo, Redis, Logstash, Kibana, Flask et profil STREAM Kafka/Filebeat ; limites mémoire, healthchecks, volumes.
- Template `logs-*`, pipelines CSV et JSON, jeux synthétiques non sensibles.
- Scripts de diagnostic, mapping et initialisation Kafka ; bus Kafka/Redis au niveau interface.

## Résultat contrôles statiques

- PASS : composition YAML (8 services, limites RAM, profils), mapping JSON et 200 journaux synthétiques.
- NON EXÉCUTÉ : pytest faute de paquets installés et d’accès réseau ; Docker absent de ce runtime.

## À valider sur Windows/WSL2 avec Docker Desktop

- Disponibilité réelle des images et compatibilité Compose/config Logstash/Kibana.
- Démarrage de tous les services CORE et mesure mémoire/CPU ; test séparé STREAM.
- Création du template avant indexation et visibilité d'événements dans Discover Kibana.
- Vérification des permissions d'écriture du dossier `datasets/rejected` monté dans Logstash.
- Honeypot : aucun VPS confirmé, ne pas déployer de service ouvert à Internet.
- OpenSSH historique : téléchargement et parsing non réalisés ; corpus non intégré.

## Non implémenté en S1 (planifié S2–S6)

Upload, authentification/RBAC, moteur de recherche, dashboards finaux, alerting, SOAR, ML, streaming temps réel effectivement câblé, rapport conformité, notification externe et tests de performance.

## Décisions

- CORE prioritaire ; STREAM optionnel.
- Versioning de tous les schémas et absence de secrets dans git.
- Events simulés RFC 5737, clairement distincts des traces réelles.

## Risques

- 12 Go RAM, image Kibana ou Kafka lourde ; dépendance à Docker Desktop.
- S1 architecture cible plus vaste que les scénarios réellement intégrés.
- L'interface Redis EventBus utilise Redis Streams pour la persistance ; Pub/Sub seul non durable.
