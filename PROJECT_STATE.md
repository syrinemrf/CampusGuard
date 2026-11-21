# PROJECT_STATE — CampusGuard / Sentinel

**Date de situation :** 20 novembre 2026. **Branche de travail :** `feat/s2-auth-upload-search` (CORE fusionné dans `main`, PR #1).
**Encadrant :** Mohamed Najeh Issaoui. **Méthode :** Kanban Jira (projet `KAN`), WIP ≤ 2, un ticket n'est clôturé qu'avec une preuve.

## Vue d'ensemble

| Tranche | Contenu | Preuve automatique | Preuve sur la stack Docker réelle |
|---|---|---|---|
| S1 / CORE | Docker Compose ELK + MongoDB + Redis + Flask, ingestion synthétique, mapping strict | 21 tests | **`verify_core` 8/8** (31 oct.) — `docs/evidence/CORE_VALIDATION_2026-10-31.md` |
| S2 | Authentification/rôles, upload CSV/JSON/TXT, ingestion Logstash, statut mesuré, recherche, export, API + Swagger | 145 tests | **`verify_s2` 18/18** (7 nov.) — `docs/evidence/verify_s2.json` |
| S3 | Centre de pilotage, 3 dashboards Kibana thématiques (paysage), modal de détail, 404, mobile, préférences, requête avancée Lucene / Query DSL | 63 tests | **`verify_s3` 13/13** (13 nov.) — `docs/evidence/verify_s3.json` |
| S4 | Alerting (module G) + réponse SOAR-lite (blocage d'IP local à durée limitée) | 39 tests | **`verify_s4` 21/21** (13 nov.) — `docs/evidence/verify_s4.json` |
| S5 | Temps réel (module H) : sshd réel → Filebeat → Kafka → Logstash → WebSocket ; escalade, veille, commentaires ; rapport PDF mensuel | 32 tests | `verify_s5` à exécuter sur la stack (script prêt) |
| S6 | Expériences ML/NLP (règles vs Isolation Forest, TF-IDF vs MiniLM vs Drain3), Isolation Forest dans le worker ; tests de charge, sécurité, reprise | 11 tests + expériences | `docs/experiments/S6_EXPERIENCES.md` ; `security_check`, `recovery_check`, Locust à exécuter sur la stack |

`python -m pytest -q` → **311 passed** (MongoDB, Redis et Elasticsearch simulés par mongomock, fakeredis et un faux client ES ;
Docker, Logstash et Kibana ne sont pas lancés par les tests). Les pages ont aussi été contrôlées dans Chromium (bureau 1440 px et
mobile 390 px) sur données simulées.

## S3 — socle obligatoire terminé (13 novembre 2026)

Deux tableaux de bord **complémentaires**, sans graphique en double :

- **Centre de pilotage** (page d'accueil de l'application) — *qu'est-ce qui demande une action maintenant ?*
  KPI d'authentification (échecs, taux de réussite, IP en échec, comptes visés) comparés à la période précédente de même durée
  (24 h / 7 j / 30 j / 90 j, période mémorisée par utilisateur) ; alertes à traiter ; 5 IP prioritaires cliquables vers l'explorateur
  pré-filtré (avec badge « bloquée ») ; **santé mesurée** de la plateforme : services, worker d'alertes, pipelines Logstash
  (événements reçus / écrits via l'API 9600), fraîcheur par source, lignes rejetées (dead letters), imports partiels ou en échec.
  API : `GET /api/overview` (cache Redis 30 s).
- **Dashboard Kibana « Sentinel · Analyse sécurité »** — *comprendre et explorer* : mode d'emploi, filtres interactifs
  (service, niveau, résultat), part des échecs dans le temps (aire à 100 %), carte de chaleur heure × jour des échecs (champs
  runtime `hour_of_day` / `day_of_week` en heure de Tunis, rien n'est réindexé), top IP, comptes les plus visés, histogramme par
  niveau, pays d'origine (GeoIP), alertes par gravité et par règle (index `sentinel-alerts-*`). 2 data views, 12 visualisations,
  1 dashboard, générés par `scripts/build_kibana_objects.py` et vérifiés champ par champ contre les templates Elasticsearch.
- Interface : détail d'un événement dans une **fenêtre modale** accessible depuis les résultats (la page `/events/<id>` reste le lien
  partageable), page 404/403 utile, fil d'Ariane, messages flash, déconnexion accessible sur mobile (et identifiant de session
  détruit à la déconnexion).

## S4 — détection et alerting (13 novembre 2026)

**Statut : VALIDÉ sur la stack Docker réelle le 13 novembre 2026 (`verify_s4` 21/21)** : attaque synthétique → Logstash → Elasticsearch → worker → 6 alertes (force brute, credential stuffing, injection SQL, élévation de privilèges, hors horaires, pays non autorisé via GeoIP 8.8.8.8 → US) → e-mail reçu dans Mailpit avec graphique PNG → webhook reçu → IP bloquée 15 min dans Redis → *silencing* (1 seule alerte, 4 occurrences) → prise en compte puis résolution → MTTR → déblocage audité.

- **Règles** (MongoDB `alert_rules`) : 4 types de condition — seuil, valeurs distinctes, motif regex, absence de logs ; fenêtres 5 min,
  15 min, 1 h, 24 h ; gravités faible → critique ; option « hors horaires ». **8 règles par défaut du scénario C** : force brute
  (5 échecs / 5 min → blocage), credential stuffing, pays non autorisé (GeoIP), connexion hors horaires, élévation de privilèges,
  injection SQL, pic d'erreurs (> 100/h), silence (désactivée par défaut).
- **Éditeur** (`/alerts/rules`) : requête Elasticsearch `query_string`, **test avant activation** (groupes qui déclencheraient +
  requête exacte), activation/désactivation, suppression des règles personnalisées. Administrateur seulement pour enregistrer.
- **Worker séparé** (`alert-worker`, `python -m app.alerting.worker`) : cycle toutes les 30 s, verrou Redis (un seul exécutant),
  battement de cœur, erreur d'une règle enregistrée sans bloquer les autres, reprise après exception. Choix assumé : boucle simple
  plutôt que Celery (pas de broker ni de beat pour un seul job périodique, ~150 Mo économisés), propriétés équivalentes testées.
- **Anti-bruit** : *silencing* (une seule alerte par règle + groupe tant qu'elle est ouverte, seules les occurrences augmentent) et
  *cooldown* configurable par règle (clé Redis à durée de vie).
- **Notifications** : e-mail SMTP (Mailpit en laboratoire, <http://localhost:8025>) avec modèle HTML, graphique PNG des événements en
  pièce jointe et liens ; webhook générique, Slack, Discord, Teams ou modèle JSON personnalisé ; **retry** 3 essais (1 s, 2 s) ;
  chaque tentative est enregistrée sur l'alerte. Récepteur de démonstration intégré (`/hooks/demo/<jeton>`).
- **Incidents** : prise en compte → résolution avec note, historique, alertes par jour, top 10 des règles, **MTTR** ; copie des
  alertes dans Elasticsearch pour Kibana. Alertes visuelles : badge dans la navigation, compteur dans le titre de l'onglet,
  notification du navigateur sur demande.
- **SOAR-lite** : blocage d'IP **local** (l'application répond 403), durée limitée (15 min par défaut), liste `BLOCK_NEVER`,
  déblocage manuel (interface ou `flask --app app.main unblock-ip <ip>`), historique MongoDB et audit. Aucune action réseau.
- **Boucle complète réelle** : les connexions à l'application elle-même sont envoyées à Logstash ; une force brute contre la page de
  connexion est donc détectée et bloquée de bout en bout (`verify_s4.py --self-block`).
- **Scénario reproductible** : `scripts/simulate_attack.py` (adresses de documentation RFC 5737, une seule IP publique d'exemple
  pour la GeoIP).

## S5 — temps réel et incidents (20 novembre 2026)

- **Données réelles** : `scripts/replay_openssh.py` rejoue les 2 000 lignes du serveur LabSZ (Loghub) au rythme d'origine
  accéléré, horodatées maintenant, au format syslog. Pseudonymisation : /16 conservé (GeoIP juste), fin d'adresse hachée.
- **Chaîne** : fichier → Filebeat (tail) → Kafka `logs.auth` (profil `stream`, topic créé par `kafka-init`) → pipeline
  Logstash `stream-security` (grok + classement sshd, une tentative = un échec) → `logs-ssh-*` → Redis Pub/Sub. Sans Kafka :
  TCP 5140. Logstash publie après l'indexation : ce qui s'affiche est déjà cherchable.
- **WebSocket** `/ws/live` (flask-sock, même origine exigée, session obligatoire), envois groupés par 250 ms, métriques chaque
  seconde (logs/s, erreurs/min, latence médiane et p95, requêtes en cours, utilisateurs connectés). Page « Flux en direct » :
  filtres niveau/source/texte, pause avec mise en attente, tampon de 500 lignes, reconnexion avec délai croissant.
- **Incidents** : escalade N2 (15 min) / N3 (1 h) des alertes non prises en compte, gravité relevée, destinataires par niveau ;
  mise en veille 15 min à 24 h avec réveil automatique ; fil de commentaires.
- **Rapport mensuel de conformité** (PDF ReportLab) : 6 contrôles chiffrés, authentifications par jour, origine des attaques,
  alertes et escalades, blocages, audit. Page `/reports`, API `/api/reports/monthly`.
- Corrigé : statistiques globales et graphiques Chart.js de l'accueil (Module 3 du sujet) ; la vue d'ensemble Kibana ne
  répète plus l'accueil ; politique `restart: unless-stopped` sur les services longs ; injection d'opérateur MongoDB au login
  (renvoyait 500, trouvé par le test de sécurité).

## S6 — expériences (20 novembre 2026)

Résultats et protocole : `docs/experiments/S6_EXPERIENCES.md`. En bref : les règles trouvent 10 des 29 IP attaquantes
réelles (F1 0,46), Isolation Forest 24 (F1 0,77) avec 11 IP légitimes signalées contre 4 ; décision : règles pour bloquer,
Isolation Forest pour signaler (règle `ml-anomaly-ssh`, sans blocage). Regroupement des messages : le masquage double la GA,
MiniLM n'apporte rien sur sshd pour un coût 500 fois supérieur, Drain3 retrouve exactement les 14 types.

## Preuves sur la stack réelle (13 novembre 2026)

- `docs/evidence/verify_s3.json` : **13/13** — 2 data views (champs runtime), 12 visualisations, dashboard, export de 15 objets et ré-import sans erreur, iframe, champs du mapping réel, 525 documents, carte de chaleur calculée par Elasticsearch, page `/kibana` de l'application.
- `docs/evidence/verify_s4.json` : **21/21** (détail ci-dessus). Option non encore exécutée : `--self-block` (auto-protection de la page de connexion).
- Historique : `verify_s3_2026-11-07.json` (11/11, première version à 4 visualisations), `verify_s2.json` (18/18), `CORE_VALIDATION_2026-10-31.md` (8/8).

## Limites assumées

- La normalisation est faite par l'application, Logstash est la seconde validation ; horodatages sans fuseau supposés UTC et signalés.
- Motifs `sshd` du parseur TXT heuristiques, non mesurés sur le corpus OpenSSH complet (KAN-15).
- La mesure mémoire avec la webapp, le worker et Mailpit reste à refaire (`scripts/feasibility.ps1`, KAN-14). Ajout S4 :
  `alert-worker` 160 Mo et `mailpit` 64 Mo de limite.
- Gestion des utilisateurs par l'interface : non prévue (création par la CLI).

## Git et coordination externe

- Dépôt : <https://github.com/syrinemrf/CampusGuard>, branche `feat/s2-auth-upload-search`.
- Jira (`KAN`) est tenu à jour avec, pour chaque ticket, ce qui est fait, la preuve et ce qui manque.

## Prochaine tranche (S7)

Exécuter sur la stack : `verify_s5`, `security_check`, `recovery_check`, Locust (100 utilisateurs). Recette finale,
installation sur une autre machine, rapport technique, slides, vidéo.
