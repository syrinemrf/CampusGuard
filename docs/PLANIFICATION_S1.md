# CampusGuard — Kanban S1 (24–30 octobre 2026)

Source de vérité : planification académique, page 2. Méthode : **Kanban** ; pas de sprints. Responsable : Syrine Maaref ; validation : M. Mohamed Najeh Issaoui.

| Date cible | Livrable officiel | Tickets Jira | Preuve | Statut de validation |
| --- | --- | --- | --- | --- |
| 24–25 oct. | 1. Rédiger l’analyse fonctionnelle et le backlog | KAN-4, KAN-8, KAN-19 | `docs/ANALYSE_FONCTIONNELLE.md`, tickets Jira et ce tableau | Rédigé, revue externe en attente |
| 26–27 oct. | 2. Dessiner les maquettes et les modèles de données | KAN-5, KAN-9, KAN-10, KAN-11 | Figma, `docs/ARCHITECTURE.md`, template ECS | Préparé, revue de qualité en attente |
| 26–29 oct. | 3. Sélectionner et préparer les données de sécurité | KAN-7, KAN-15, KAN-16 | `docs/DONNEES_SECURITE.md`, scripts, samples | Synthétique prêt ; Loghub téléchargement/test restant |
| 28–30 oct. | 4. Créer le dépôt Git et installer la stack avec Docker | KAN-6, KAN-12, KAN-13, KAN-14, KAN-17, KAN-18 | Commit local, Compose, probes | Git local oui ; dépôt distant et Docker local non validés |

**WIP maximal : 2 tâches en cours.** Colonnes Jira existantes : Idea (backlog), À faire, En cours, Revue en cours, Terminé(e). Un ticket ne passe à Terminé qu'avec sa preuve. Priorités P0 : boot Docker, mesure de RAM, ingestion et indexation. Dépendances : F01→architecture→mappings/pipelines→Docker→données réelles→validation Kibana. Revue de jalon S1 datée du 30/10, non simulée rétrospectivement.

## Critères stricts de fin S1
- Analyse : traçabilité du sujet, rôles, cas d’usage, backlog priorisé.
- Maquettes : navigation lisible, 6 écrans desktop, 2 variantes mobiles, pages Figma séparées, modèles alignés à ECS/Mongo/Redis.
- Données : source réelle identifiée, extraction/replay reproductible et provenance documentée, aucune affirmation non prouvée sur le volume/labels.
- Infrastructure : dépôt Git distant accessible **et** `docker compose up` testé, résultats de `docker stats` sauvegardés et logs visibles dans Kibana.

## Limites
L'environnement de l'assistant ne possède pas Docker et le connecteur GitHub ne fournit pas d'action de création de dépôt ; ces points ne sont pas déclarés « terminés ». Le partage Jira avec l'encadrant nécessite l'invitation au site si son compte n'y existe pas.
