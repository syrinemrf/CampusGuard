# PROJECT_STATE — CampusGuard / Sentinel
**Date de situation :** 30 octobre 2026 — correctif S1. **Encadrant :** Mohamed Najeh Issaoui.

## Suivi officiel S1 (Kanban, pas Scrum)
1. Analyse fonctionnelle + backlog : rédigés, revue enseignante non réalisée (`KAN-4`, `KAN-8`, `KAN-19`).
2. Maquettes + modèles : Figma 3 pages (Starter) avec 6 desktop et 2 mobile ; modèles ECS/Mongo/Redis ; revue UX souhaitée (`KAN-5`, `KAN-9`, `KAN-10`, `KAN-11`).
3. Données de sécurité : générateur synthétique fonctionnel ; source officielle Loghub identifiée et échantillon lu via connecteur ; le dataset complet n'est pas téléchargé/converti, script reproductible fourni (`KAN-7`, `KAN-15`, `KAN-16`).
4. Git et Docker : dépôt **Git local initialisé avec commit** ; dépôt distant GitHub **inexistant**. Docker Compose et probes préparés, exécution réelle sur poste **non effectuée** (`KAN-6`, `KAN-12`–`KAN-14`, `KAN-17`, `KAN-18`).

## Éléments vérifiés
- `git log`: commit `77db26e` (avant dernier complément documentaire).
- Python syntaxe valide (`compileall`).
- YAML Compose analysable (8 services).
- GitHub connecté (`syrinemrf`) mais **aucun outil pour créer un repository**.
- Jira : 4 Epics = 4 tâches officielles ; 12 tâches planifiées, responsables/échéances, états de Kanban modifiés.
- Figma : 3 pages (limite Starter), 6 desktop et 2 mobile, palette éclaircie. Prototype non interactif.

## Non validé / dépendance externe
- `docker compose up`, `docker stats`, indexation Elasticsearch et consultation Kibana : Docker indisponible dans le runtime.
- `pytest` : imports Flask impossibles sans les dépendances (voir `app/requirements.txt`), résultat non réussi.
- Source historique OpenSSH : origine officielle attestée, script de récupération, pas de dataset complet intégré dans le dépôt.
- Invitation `issaoui.mn@itbs.tn` : compte Jira inexistant à la recherche, outil d'invitation non disponible.

## Décisions
- Méthode Kanban avec WIP limité lors de l'exécution réelle ; revue et preuves obligatoires.
- Priorité au socle CORE ; Kafka STREAM est optionnel pour S1 en raison de 12 Go de RAM.
- Ne jamais faire passer un ticket en Terminé sans test réel.
