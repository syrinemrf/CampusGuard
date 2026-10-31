# Passage de contexte ChatGPT → Codex — CampusGuard

> Situation vérifiée le **31 octobre 2026** à partir du dépôt GitHub et de Jira. Le texte de cette conversation ChatGPT ne se synchronise pas automatiquement vers Codex. Ce document remplace une transcription brute de l'historique.

## Liens partagés
- GitHub : https://github.com/syrinemrf/CampusGuard — branche `main` ; il existe déjà trois commits récents le 30 octobre (dont `4c31ed2`).
- Jira Kanban : https://itbs-team-syrinem.atlassian.net/jira/software/projects/KAN/boards/2 ; 60 tickets CampusGuard, 10 Epics/50 tâches, S1–S7.
- Figma principal **NON FINALISÉ** : https://www.figma.com/design/6iwEDizCye867D8dfoGJk7 ; plusieurs fichiers séparés antérieurs et quota Figma Starter atteint. HTML joint en source de vérité UI.
- Encadrant Mohamed Najeh Issaoui ; son compte apparaît actif et assignable dans Jira, mais son droit d'accès final au projet n'est pas vérifié.

## Exigences officielles, sans interprétation libre
- **Obligatoire :** upload CSV, JSON, TXT ; drag/drop, progression, validation et prévisualisation de 10 lignes ; statut et historique dans MongoDB ; deux pipelines Logstash ; index template Elasticsearch ; trois visualisations Kibana + un dashboard exporté ; interface responsive ; recherche texte/filtres/pagination 50/tri/détail/export CSV ; historique des recherches ; stack Docker Compose complète.
- **Avancé pour viser 20/20 : au moins deux modules.** Décision : G (règles/alertes/notifications/gestion incidents) et H (streaming, live tail, métriques). ML Python/Isolation Forest uniquement après, sans dépendre d'Elastic ML payant.
- **Parcours de démonstration prioritaire :** connexion → importer un log → prévisualiser → valider → ingestion → retrouver dans Elasticsearch/Kibana/recherche → alerte SSH → acquittement/résolution → blocage TTL local → logs live.

## État VÉRIFIÉ du dépôt GitHub au 31 octobre
- Présents : `.env.example`, `README.md`, `PROJECT_STATE.md`, `docker-compose.yml`, `app/`, `bus/`, `datasets/`, `docs/`, `ingestion/`, `scripts/`, `simulator/`, `tests/`.
- `app/main.py` contient **seulement** `GET /`, `GET /health`, `GET /ready`. Upload, recherche, dashboard, auth, alertes **non développés** à ce stade.
- Compose : ELK 8.19.10 par défaut, Mongo 7, Redis 7.4, Flask/gunicorn. Services Kafka/Filebeat sous profil `stream`, mais **pipeline stream de bout en bout non prouvé**.
- Pipelines Logstash `csv.conf`, `json.conf` et mapping ECS initial présents ; simulateur JSONL/CSV présent.
- `tests/test_foundation.py` définit **6 tests** ; aucune exécution GitHub Actions, aucun dossier `.github/workflows` à ce jour.
- `scripts/prepare_openssh.py` sait télécharger/transformer `OpenSSH_2k.log` (jeu d'échantillon), mais import réel, qualité parsing et comptage dans ES non démontrés. Ne pas confondre avec l'archive OpenSSH plus grande mentionnée dans les sources.
- `PROJECT_STATE.md` et `docs/REVUE_S1.md` sont périmés : indiquent à tort que le dépôt GitHub distant n'existe pas. Les rectifier avec des preuves et une date.
- **Pas de preuve de `docker compose up` réussi sur le PC**, ni de logs réellement visibles dans Kibana. Pas de preuve de tests pytest exécutés.

## État VÉRIFIÉ de Jira
- S1, quatre Epics officiels : `KAN-4` analyse/backlog ; `KAN-5` maquettes/modèles ; `KAN-7` données ; `KAN-6` Git et Docker.
- Ces 4 Epics sont actuellement `Terminé(e)`, **incohérence** : les tâches critiques `KAN-13` (Docker), `KAN-14` (RAM), `KAN-15` (Loghub), `KAN-16` (pipelines), `KAN-18` (Kibana) sont ouvertes. Ne pas prétendre clôturées ; proposer correction si Jira est accessible.
- S2 Epic `KAN-20` 31 oct.–6 nov. : auth `KAN-39`, upload `KAN-40`, ingestion `KAN-41`, recherche `KAN-42`.
- S3 `KAN-21` 7–13 nov. : MVP complet ; S4 `KAN-22` 14–20 nov. : alertes ; S5 `KAN-23` 21–27 nov. : live ; S6 `KAN-24` 28 nov.–4 déc. : expériences/QA ; S7 `KAN-25` 5–11 déc. : recette/remise.
- Kanban, pas Scrum, WIP maximum 2 ; toujours lier preuves, tests, code aux tickets.

## Pourquoi ce document existe
Codex doit travailler à partir du **dépôt réel**, de la consigne de l'enseignant et des critères mesurés. Il ne faut pas croire les précédentes affirmations « tout est fait » : le MVP n'est pas encore développé. Les maquettes du HTML sont des références d'interface, pas un backend.

## Règles de priorité et calendrier
1. **Aujourd'hui :** rendre Compose CORE fonctionnel et log CSV/JSON visible dans Kibana ; enregistrer `docker stats` (12 Go RAM) et une preuve réexécutable.
2. **S2 :** login + upload validé + métadonnées + recherche API + test E2E.
3. **S3 :** frontend, KPI, recherche/pagination/export, Kibana 3 graphiques + export dashboard, rôle/cache/OpenAPI si possible.
4. **S4/S5 :** G et H avec tests, puis innovations si du temps reste.
5. **S6/S7 :** performance, CI, guide, rapport, vidéo, présentation, recette sur machine vierge.

## Priorités de collaboration
- Codex édite/teste localement le repo, pousse commits ou PR GitHub.
- ChatGPT/Jira servent au pilotage et à la revue ; communiquer lien PR, commandes et métriques dans les tickets.
- Si le connecteur GitHub de ChatGPT refuse l'écriture (403 déjà observé), Codex utilise ses propres autorisations Git dans son environnement ; ne pas présumer que les autorisations sont partagées.
