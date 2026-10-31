# Message à coller dans Codex — premier lancement

Tu es l'ingénieur senior chargé de terminer CampusGuard/Sentinel, projet Big Data sécurité/authentification de l'ITBS. Travaille **directement dans ce dépôt Git**, pas dans un nouveau projet. Commence par lire `AGENTS.md`, `docs/CODEX_HANDOFF.md`, `docs/CODEX_EXECUTION_PLAN.md`, le cahier des charges officiel dans `docs/reference/`, puis l'état du code, `README.md` et `PROJECT_STATE.md`.

**Ta mission immédiate : implémenter et TESTER le Gate A (S1 rattrapage) de bout en bout.**
1. Audit très bref du dépôt (pas de réécriture générale), repère les incohérences entre code et docs et crée une branche `fix/core-e2e`.
2. Exécute `docker compose config -q` ; démarre progressivement le profil CORE sur la machine ; corrige erreurs de service, santé, mapping et pipeline en gardant une empreinte mémoire adaptée à 12 Go RAM.
3. Génère et injecte des logs JSONL/CSV ; vérifie les comptes réels dans Elasticsearch ; crée/configure la data view Kibana si nécessaire et documente la recette. Teste aussi le rejet d'un fichier invalide.
4. Lance `python -m pytest -q`, ajoute les tests essentiels manquants, ajoute CI GitHub Actions minimal seulement si cela ne retarde pas le fonctionnement local.
5. Mets `PROJECT_STATE.md` et le README à jour avec mesures réelles, preuves et limitations. Informe-moi des résultats PASS/FAIL et des ports/adresses.
6. Commit les changements sur la branche ; ouvre une PR vers `main` si autorisé. Ne merge pas sans revue et ne touche pas à des secrets.

**Contraintes :** pas de Kafka/ML/LLM ni de refonte Figma maintenant ; priorité au parcours réel `fichier → Logstash → Elasticsearch → Kibana`. N'affirme jamais qu'un test a réussi sans exécution. Ne me sollicite que pour un vrai blocage (accès Docker, permission, secret ou décision à risque). Ensuite seulement, propose le Gate C : login + upload + métadonnées Mongo (KAN-39–41).
