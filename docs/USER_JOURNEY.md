# UX — CampusGuard Sentinel | S1

## Personae

- **Analyste SOC** : enquête rapide sur un pic de connexions échouées, recherche par IP, service et période, agrégation visuelle.
- **Administrateur** : vérifie la santé des sources et de l'ingestion ; paramètre utilisateurs, règles et connexions.
- **Auditeur** : consulte des incidents et exporte des traces documentées en lecture seule.

## Parcours principal

1. Connexion et ouverture du dashboard SOC (KPI globaux, timeline, gravité des alertes).
2. Upload CSV/JSON/TXT, prévisualisation des 10 premières lignes et validation du schéma.
3. Contrôle statut « reçu → validé → indexé » ou message d'erreur accessible.
4. Recherche par dates, IP, niveau, service et texte libre ; rappel des 5 dernières requêtes.
5. Exploration du log avec détails ECS, géolocalisation **approximative** et référence à la source.
6. Accusé de réception d'une alerte, justification, escalade ou résolution avec audit immuable.

## Écrans Figma attendus

Dashboard SOC, Upload de fichiers, Explorateur de logs, Fiche événement, Centre d'alertes/incidents, Paramètres et sources. Design system : fond ardoise nuit, surfaces bleu anthracite, accent turquoise/menthe, rouge réservé aux incidents critiques, vert réservé au statut sain ; typographie à fort contraste, focus visible, labels complets, pas d'information véhiculée uniquement par couleur.

## Critères d'acceptation UX

Viewport 1440x900 desktop et version mobile ~390 px ; parcours accessible au clavier dans l'implémentation ; barres de chargement explicites ; états vides/chargement/échec ; confirmation avant toute action de réponse ; filtre période clairement visible ; tableaux paginés ; chiffres de démonstration **étiquetés fictifs** et jamais présentés comme données réelles.

## Figma — livrables réels

Huit frames éditables : six écrans desktop 1440×900 et variantes mobiles 390×844 pour Dashboard SOC et Centre d’alertes. Fichier : https://www.figma.com/design/6iwEDizCye867D8dfoGJk7. Les métriques affichées sont fictives et les interactions ne sont pas encore prototypées.
