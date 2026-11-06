# API REST CampusGuard / Sentinel (S2)

Spécification machine-lisible : `GET /api/openapi.json` (OpenAPI 3.0.3).
Documentation interactive : <http://localhost:8000/api/docs> (Swagger UI embarqué, aucune ressource externe).
Un test (`tests/test_s2_api.py`) compare la spécification et la table de routage Flask : une route non documentée, ou documentée mais inexistante, fait échouer la suite.

## Authentification et sécurité

| Mécanisme | Détail |
|---|---|
| Session | `POST /api/auth/login` `{"username","password"}` → cookie `HttpOnly`, `SameSite=Lax` contenant un identifiant opaque ; la session vit dans Redis (`sentinel:session:<id>`, TTL 2 h, identifiant renouvelé à la connexion). |
| CSRF | La réponse de connexion contient `csrf_token`. Toute requête `POST`/`DELETE` doit envoyer `X-CSRF-Token: <jeton>`. La connexion JSON est la seule exception. |
| Rôles | `admin`, `analyst` (envoi + confirmation + annulation d'imports), `auditor` (lecture seule). Un rôle insuffisant renvoie `403`. |
| Anti-force brute | 5 échecs / 300 s par IP ou par utilisateur → `429` + `Retry-After`. Chaque tentative est tracée (`audit_actions`), jamais le mot de passe. |
| Limite de débit | 300 requêtes/min par utilisateur (par IP avant connexion) sur `/api/*`, réglable (`API_RATE_LIMIT_PER_MIN`) → `429` + `Retry-After`. |

Format d'erreur unique : `{"error": "<code>", "message": "<texte>", ...}`.

## Routes

| Méthode | Chemin | Rôle minimum | Description |
|---|---|---|---|
| POST | `/api/auth/login` | — | Connexion |
| GET | `/api/auth/me` | auditor | Utilisateur courant + jeton CSRF |
| POST | `/api/uploads` | analyst | Envoi + validation. `201` validé, `422` rejeté, `409` doublon, `413` trop gros, `415` extension interdite |
| GET | `/api/uploads` | auditor | Imports (statut re-mesuré pour ceux en cours) |
| GET | `/api/uploads/{id}` | auditor | Détail : aperçu 10 lignes, statistiques, erreurs, statut |
| POST | `/api/uploads/{id}/confirm` | analyst | Lance l'ingestion Logstash (`202`) |
| DELETE | `/api/uploads/{id}` | analyst | Annule un import non confirmé |
| GET | `/api/search` | auditor | Recherche paginée (voir paramètres) |
| GET | `/api/search/facets` | auditor | Valeurs disponibles (niveaux, services) |
| GET | `/api/search/history` | auditor | Dernières recherches de l'utilisateur (MongoDB) |
| GET | `/api/search/export` | auditor | Export CSV des résultats (plafonné, protégé contre l'injection de formules) |
| GET | `/api/events/{id}` | auditor | Document complet d'un événement |
| GET | `/api/stats` | auditor | KPI du tableau de bord |
| GET | `/api/v1/logs` | auditor | Alias stable de la recherche |
| GET | `/api/v1/logs/{id}` | auditor | Alias de `/api/events/{id}` |
| GET | `/api/v1/files` | auditor | Alias de `/api/uploads` |
| GET | `/api/v1/stats` | auditor | Alias de `/api/stats` |
| GET | `/api/openapi.json` | auditor | Spécification OpenAPI |

### Paramètres de recherche

`q` (texte libre), `start` / `end` (UTC, date seule = journée entière), `level`, `service` (listes séparées par des virgules), `outcome` (`success|failure|unknown`), `ip` (adresse ou CIDR), `user`, `upload_id`, `sort_by` (`timestamp|level|service`), `sort` (`asc|desc`), `page`, `size` (≤ 100, fenêtre `page × size` ≤ 10 000). Toute valeur invalide renvoie `400` avec le détail par champ. Les résultats sont mis en cache 30 s dans Redis (`nocache=1` pour contourner ; le champ `cached` l'indique).

## Exemple

```bash
curl -s -c jar -H 'Content-Type: application/json' \
     -d '{"username":"analyste","password":"…"}' http://localhost:8000/api/auth/login
# → {"csrf_token":"…","role":"analyst",…}

curl -s -b jar 'http://localhost:8000/api/v1/logs?level=WARNING,ERROR&outcome=failure&size=5'

curl -s -b jar -H 'X-CSRF-Token: …' -F file=@datasets/samples/auth.jsonl http://localhost:8000/api/uploads
```

## Cycle de vie d'un import

`received → validated → ingesting → indexed | partial | failed` (ou `rejected` à la validation, `cancelled`).
Les états `indexed`, `partial` et `failed` sont **mesurés** (comptage Elasticsearch par `labels.upload_id` + lignes rejetées par Logstash), jamais supposés. Au-delà de 300 s sans résultat, l'indicateur `stalled` est ajouté sans prétendre à un échec.
