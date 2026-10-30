# CampusGuard — Analyse fonctionnelle initiale (S1)

**Version :** 0.1 ; **responsable :** Syrine Maaref ; **encadrant :** Mohamed Najeh Issaoui ; **périmètre :** système local de laboratoire.

## 1. Problématique et proposition de valeur

Les journaux d'authentification, de pare-feu, d'audit administratif et d'applications web sont fragmentés. Il est difficile de reconstruire rapidement une séquence d'accès abusif, de mesurer le risque et de conserver une traçabilité. CampusGuard propose une centralisation consultable et un moteur « Sentinel » d'alertes compréhensibles et d'actions réversibles sur un environnement de démonstration.

## 2. Acteurs et droits

| Acteur | Droits cibles | Restrictions |
| --- | --- | --- |
| Administrateur | sources, utilisateurs, règles, paramètres, incidents | journalisation de toute réponse |
| Analyste SOC | rechercher, enquêter, acquitter/escalader une alerte, simulations autorisées | pas d'administration globale |
| Auditeur | lecture, export de preuves et rapports | pas de blocage ou modification |
| Système ingestion | transformer/indexer les événements | pas d'accès UI administratif |
| Encadrant | accès Jira/livrables, revue | pas de données réelles sensibles |

## 3. Objectifs fonctionnels — MVP obligatoire

F01 : importer CSV/JSON/TXT, avec limites/contrôles, aperçu et statuts ; F02 : normaliser et indexer les logs ; F03 : afficher les métriques globales ; F04 : rechercher et filtrer par période, niveau, service ; F05 : explorer le détail d'un log ; F06 : export CSV ; F07 : historique utilisateur MongoDB ; F08 : visualisations Kibana ; F09 : lancer via Docker Compose ; F10 : gérer les erreurs, les refus et la transparence des résultats. Les fonctions F01–F08 sont **planifiées S2–S3**, et non implémentées en S1.

## 4. Modules avancés visés

G (alertes, notifications, ack/resolve/snooze), H (tail et compteurs live), I (Isolation Forest + données étiquetées), K/L (tests, automatisation, auto-surveillance). Le module de réponse SOAR-lite est limité au service applicatif de démonstration ; aucune règle de pare-feu du poste n'est modifiée.

## 5. Cas d'utilisation prioritaires

**UC01 Importer :** un analyste sélectionne un fichier, visualise les 10 premières lignes et valide ; le fichier est accepté/rejeté avec motif ; statut ingestion disponible. **UC02 Enquêter :** l'analyste filtre les échecs de connexion d'une IP, consulte la chronologie et exporte un CSV. **UC03 Répondre :** une IP déclenche 5 échecs en 5 minutes ; une alerte est créée ; le middleware du service de démonstration applique un TTL ; l'opérateur peut débloquer et chaque action est auditée. **UC04 Auditer :** l'auditeur génère un rapport retraçant alertes, accès admin et temps de réaction. **UC05 Simuler :** un acteur autorisé lance des attaques fictives étiquetées sans viser de système externe.

## 6. Règles métier

BR01 : identifiant événement source + hash payload pour limiter les doublons ; BR02 : `@timestamp` horodatage UTC, `event.ingested` date de réception ; BR03 : champs `service.name` et `log.level` sur chaque événement ; BR04 : 5 échecs par source IP en fenêtre de 5 minutes, TTL de blocage 1 heure configurables ; BR05 : toutes les actions de réponse sont attribuées à un compte et horodatées ; BR06 : pas de stockage des mots de passe tentés en clair ; BR07 : une alerte doit porter une explication lisible et un lien d'enquête.

## 7. Exigences non fonctionnelles

NFR01 : reproductibilité sur Docker Compose v2 ; NFR02 : fonctionnement CPU-only, 12 Go RAM sous condition de faisabilité ; NFR03 : secrets uniquement via env, pas dans git ; NFR04 : UI desktop et mobile ; NFR05 : traces JSON, statut de santé ; NFR06 : gestion des erreurs (parse, temps, IP invalides) ; NFR07 : 70%+ de couverture du socle après S2–S3 ; NFR08 : latence de détection <1s **objectif expérimental, non garanti**, mesure en S5–S6 ; NFR09 : horodatages homogènes UTC ; NFR10 : exposition des ports uniquement localhost en laboratoire.

## 8. Données et conformité

Sources : Loghub OpenSSH (historique réel à télécharger), génération Faker/simulateur étiqueté, Cowrie sur VPS isolé **facultatif** selon disponibilité. Pour la traçabilité des métriques, ne jamais mélanger les vérités terrain synthétiques et les logs réels non étiquetés sans expliciter la provenance. La géolocalisation IP ne prouve pas l'emplacement physique de l'utilisateur. Pseudonymiser les identifiants personnels dans tout rapport public. Référence au RGPD 72 h = obligation de notification conditionnelle des violations, pas garantie technique du logiciel.

## 9. Critères d'acceptation S1

A1: exigences, acteurs et parcours décrits ; A2: diagrammes et mappings relus ; A3: six maquettes modifiables ; A4: docker-compose syntaxiquement valide et healthchecks définis ; A5: événements JSON et CSV de démonstration générés ; A6: pipelines destinés à ces formats ; A7: ES template correctement typé ; A8: rapport de consommation réelle disponible après lancement par l'étudiante ; A9: vrai dataset OpenSSH téléchargé et analysé (action à effectuer) ; A10: événements visibles dans Kibana **uniquement après test Docker réussi**.

## 10. Risques

R1 RAM insuffisante : pas de Kafka en CORE ; R2 format OpenSSH incompatible : parser via `grok`/Python vers ECS après inspection ; R3 bruit des alertes : fenêtres + déduplication ; R4 fiabilité GeoIP : `unknown` plutôt que localisation inventée ; R5 exposition sécurité : localhost, labo isolé ; R6 retard S1 : reporter G/H/I sans sacrifier MVP ; R7 licences : respecter les conditions des corpus et API.
