# CampusGuard / Sentinel — instructions permanentes pour Codex

## Mission
Projet académique Big Data de Syrine Maaref (IT Business School), encadrant Mohamed Najeh Issaoui, scénario C : **sécurité et authentification**. Construire une plateforme de monitoring de logs avec ELK, MongoDB, Redis et application web Flask. Priorité : **MVP obligatoire fonctionnel et démontrable**, puis modules avancés **G (alerting)** et **H (temps réel)**. Les essais ML/NLP, Kafka et honeypot ne doivent pas retarder le socle. Remise visée autour du 12 décembre 2026 (à confirmer avec l'encadrant).

## Autorité documentaire et contexte
1. Cahier des charges du professeur : `docs/reference/Mini-Projet ELK Oct2026.pdf` (critères obligatoires et avancés).
2. Planification S1–S7 : `docs/reference/Planification_MiniProjet_Syrine_Maaref.pdf` ; cette planification **prime** sur l'ancien calendrier de quatre semaines de `Sentinel_Prompt_Directeur.md`.
3. Architecture voulue : `docs/reference/sentinel_architecture_globale_v2.png` et `docs/reference/CampusGuard_Cahier_des_charges_Analyse_Architecture_Amelioree.pdf` ; adapter selon réalité et documenter les écarts.
4. Maquettes de référence : `docs/reference/sentinel-maquettes.html` (10 vues, thème clair, reproduire de préférence avec Bootstrap/Jinja et Chart.js).
5. Contexte de transmission et état réel : `docs/CODEX_HANDOFF.md` ; plan d'exécution : `docs/CODEX_EXECUTION_PLAN.md`.
6. **Toujours lire les fichiers actuels du dépôt** ; le statut dans la documentation peut être périmé. Ne jamais supposer que le code est implémenté parce qu'un ticket Jira est marqué terminé.

## Périmètre technique
- Docker Compose v2 ; Elasticsearch/Logstash/Kibana 8.x (versions identiques et épinglées) ; MongoDB 7 ; Redis 7 ; Python 3.11, Flask 3, Gunicorn, Jinja2 ; Bootstrap 5, Chart.js ; tests pytest.
- **CORE d'abord** : fichiers CSV/JSON/TXT → validation Flask → dossier surveillé/pipeline Logstash → Elasticsearch → API/recherche → dashboard/Kibana ; MongoDB pour métadonnées/recherches ; Redis pour sessions/cache/limiteurs.
- **STREAM plus tard** : Kafka (profil séparé) + Filebeat + Redis Pub/Sub/Streams + SSE/WebSocket. Ne pas lancer Kafka en continu sur PC 12 Go sans mesures.
- Une seule machine Windows 11 + WSL2 Ubuntu + Docker Desktop ; privilégier faibles budgets RAM et le `localhost` (pas d'exposition publique).
- Données historiques Loghub OpenSSH, échantillons synthétiques à vérité terrain ; IP et secrets pseudonymisés. Honeypot uniquement si autorisé et sur machine isolée ; sinon rejeu déclaré.
- Réponse de sécurité : blocage **applicatif de laboratoire** dans Redis avec TTL et audit ; ne pas agir sur de vrais systèmes, firewalls ou IP externes.

## Définition du terminé (DoD) pour CHAQUE tâche
1. Fonctionnement démontré : tests automatisés + commande ou preuve d'intégration ; échec et cas limites couverts.
2. Pas de secret dans le dépôt ; `.env.example` seul est versionné ; validations fichiers, erreurs et horodatages UTC explicites.
3. Code propre, maintenable, commentaires utiles ; fonctions courtes, pas de features fictives ni de faux chiffres.
4. Modifier README et `PROJECT_STATE.md` pour décrire **fait / non testé / bloqué** ; ticket Jira (si accessible) avec résultats et lien du commit/PR.
5. Produire un commit ciblé sur branche dédiée (ex. `feat/core-upload`), et une PR pour revue si GitHub est autorisé. Ne pas écraser `main` ni réécrire l'historique.

## Processus de travail efficace
- Inspecter `git status`, `README.md`, `PROJECT_STATE.md`, Compose, Flask, pipelines, tests et les critères du professeur **avant de coder**.
- Effectuer une mini-audit de démarrage, puis **exécuter immédiatement les étapes réalisables** ; ne demander confirmation que pour changement destructif, secret/compte externe, environnement inaccessible ou coût réel.
- Travailler par tranches verticales finies : (1) stack CORE + données visibles, (2) import & validation, (3) recherche, (4) frontend & Kibana, (5) alerting G, (6) live H, (7) tests et livraison.
- À la fin de chaque tranche : fichiers modifiés, commandes, tests PASS/FAIL, capture/chemin de preuve, limitations, prochain ticket.
- Lancer `docker compose config -q`, `python -m pytest -q`, `docker compose ps`, et les tests d'intégration pertinents. Ne pas affirmer que Docker tourne si ces commandes ne sont pas exécutées.
- Toujours donner priorité à une démonstration complète conforme au sujet avant l'innovation ; aucun Kafka/ML tant que le MVP n'est pas couvert par tests.
- Jira Kanban : projet `KAN` ; WIP ≤ 2 ; ne jamais marquer un Epic terminé si ses tâches critiques ne le sont pas. L'accès de Codex à Jira doit être vérifié séparément.

## Sécurité et robustesse
- L'option actuelle Elasticsearch `xpack.security.enabled=false` est acceptable **uniquement pour environnement de développement local isolé**. Ports publiés sur 127.0.0.1 uniquement et avertissement dans README.
- Horodatage `@timestamp` en UTC, champs ECS `log.level`, `service.name`, `source.ip`, `event.action/outcome` et règles de qualité des événements.
- Attention à la préparation OpenSSH : la pseudonymisation doit préserver un identifiant d'IP stable pour les agrégations, sans exposer d'IP sensible ; documenter l'effet sur GeoIP.
- Utiliser des données factices TEST-NET dans les exemples ; ne pas prétendre qu'une valeur d'exemple représente une attaque réelle.
