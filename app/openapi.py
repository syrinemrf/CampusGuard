"""OpenAPI 3 description of the REST API (served at /api/openapi.json, rendered by Swagger UI at /api/docs).

A test (tests/test_s2_api.py) compares this document with the Flask routing table so it cannot drift.
"""

_SEARCH_PARAMS = [
    {'name': 'q', 'in': 'query', 'schema': {'type': 'string', 'maxLength': 256}, 'description': 'Texte libre sur le message (simple_query_string, AND).'},
    {'name': 'start', 'in': 'query', 'schema': {'type': 'string'}, 'description': 'Début (UTC) : 2026-10-30 ou ISO 8601.'},
    {'name': 'end', 'in': 'query', 'schema': {'type': 'string'}, 'description': 'Fin (UTC) ; une date seule inclut toute la journée.'},
    {'name': 'level', 'in': 'query', 'schema': {'type': 'string'}, 'description': 'DEBUG, INFO, WARNING, ERROR, CRITICAL (séparés par des virgules).'},
    {'name': 'service', 'in': 'query', 'schema': {'type': 'string'}, 'description': 'Nom(s) de service, séparés par des virgules.'},
    {'name': 'outcome', 'in': 'query', 'schema': {'type': 'string', 'enum': ['success', 'failure', 'unknown']}},
    {'name': 'ip', 'in': 'query', 'schema': {'type': 'string'}, 'description': 'Adresse IPv4/IPv6 ou CIDR.'},
    {'name': 'user', 'in': 'query', 'schema': {'type': 'string'}},
    {'name': 'upload_id', 'in': 'query', 'schema': {'type': 'string', 'pattern': '^[0-9a-f]{32}$'}},
    {'name': 'sort_by', 'in': 'query', 'schema': {'type': 'string', 'enum': ['timestamp', 'level', 'service'], 'default': 'timestamp'}},
    {'name': 'sort', 'in': 'query', 'schema': {'type': 'string', 'enum': ['asc', 'desc'], 'default': 'desc'}},
    {'name': 'page', 'in': 'query', 'schema': {'type': 'integer', 'minimum': 1, 'default': 1}},
    {'name': 'size', 'in': 'query', 'schema': {'type': 'integer', 'minimum': 1, 'maximum': 100, 'default': 50}},
]
_ID = {'name': 'event_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}
_UPLOAD_ID = {'name': 'upload_id', 'in': 'path', 'required': True, 'schema': {'type': 'string', 'pattern': '^[0-9a-f]{32}$'}}
_ERR = {'description': 'Erreur', 'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Error'}}}}


def _ok(description, schema=None):
    content = {'application/json': {'schema': schema}} if schema else None
    out = {'description': description}
    if content:
        out['content'] = content
    return out


def _search_op(summary, tag):
    return {'tags': [tag], 'summary': summary, 'parameters': _SEARCH_PARAMS,
            'responses': {'200': _ok('Résultats paginés', {'$ref': '#/components/schemas/SearchResult'}), '400': _ERR, '401': _ERR, '429': _ERR, '502': _ERR}}


def build_spec():
    secure = [{'sessionCookie': []}]
    return {
        'openapi': '3.0.3',
        'info': {'title': 'CampusGuard / Sentinel API', 'version': '2.0.0',
                 'description': ("API REST du laboratoire CampusGuard. Authentification par cookie de session (POST /api/auth/login) ; "
                                 "les requêtes POST/DELETE exigent l'en-tête X-CSRF-Token renvoyé à la connexion. "
                                 "Limite : 300 requêtes/minute et par utilisateur (HTTP 429).")},
        'servers': [{'url': '/'}],
        'tags': [{'name': 'auth'}, {'name': 'uploads'}, {'name': 'search'}, {'name': 'dashboard'}, {'name': 'v1', 'description': 'Alias stables /api/v1 du sujet (logs, files, stats).'}],
        'security': secure,
        'paths': {
            '/api/auth/login': {'post': {'tags': ['auth'], 'summary': 'Connexion (JSON)', 'security': [],
                'requestBody': {'required': True, 'content': {'application/json': {'schema': {'type': 'object', 'required': ['username', 'password'],
                    'properties': {'username': {'type': 'string'}, 'password': {'type': 'string', 'format': 'password'}}}}}},
                'responses': {'200': _ok('Session créée ; renvoie csrf_token'), '401': _ERR, '429': _ERR}}},
            '/api/auth/me': {'get': {'tags': ['auth'], 'summary': 'Utilisateur courant', 'responses': {'200': _ok('Utilisateur'), '401': _ERR}}},
            '/api/uploads': {
                'get': {'tags': ['uploads'], 'summary': 'Liste des imports (statut mesuré)', 'responses': {'200': _ok('Liste'), '401': _ERR}},
                'post': {'tags': ['uploads'], 'summary': 'Envoyer et valider un fichier (CSV, JSON, JSONL, NDJSON, TXT, LOG)',
                    'requestBody': {'required': True, 'content': {'multipart/form-data': {'schema': {'type': 'object', 'required': ['file'],
                        'properties': {'file': {'type': 'string', 'format': 'binary'}, 'source_type': {'type': 'string', 'enum': ['auto', 'csv', 'json', 'txt']}}}}}},
                    'responses': {'201': _ok('Validé : aperçu des 10 premières lignes, statistiques, erreurs'), '409': _ERR, '413': _ERR, '415': _ERR, '422': _ERR}}},
            '/api/uploads/{upload_id}': {
                'parameters': [_UPLOAD_ID],
                'get': {'tags': ['uploads'], 'summary': "Détail d'un import ; recalcule le statut s'il est en cours", 'responses': {'200': _ok('Import'), '404': _ERR}},
                'delete': {'tags': ['uploads'], 'summary': 'Annuler un import validé (non lancé)', 'responses': {'200': _ok('Annulé'), '409': _ERR}}},
            '/api/uploads/{upload_id}/confirm': {'parameters': [_UPLOAD_ID], 'post': {'tags': ['uploads'], 'summary': "Lancer l'ingestion Logstash",
                'responses': {'202': _ok('Ingestion en cours'), '409': _ERR}}},
            '/api/search': {'get': _search_op('Recherche de logs (Query DSL, pagination, tri, cache Redis 30 s)', 'search')},
            '/api/search/facets': {'get': {'tags': ['search'], 'summary': 'Valeurs de filtres (niveaux, services, période)', 'responses': {'200': _ok('Facettes')}}},
            '/api/search/history': {'get': {'tags': ['search'], 'summary': 'Dernières recherches (MongoDB)',
                'parameters': [{'name': 'limit', 'in': 'query', 'schema': {'type': 'integer', 'default': 5, 'maximum': 20}}], 'responses': {'200': _ok('Historique')}}},
            '/api/search/export': {'get': {'tags': ['search'], 'summary': 'Export CSV des résultats filtrés (plafond configurable, signalé)',
                'parameters': _SEARCH_PARAMS, 'responses': {'200': {'description': 'CSV', 'content': {'text/csv': {'schema': {'type': 'string'}}}}}}},
            '/api/events/{event_id}': {'parameters': [_ID], 'get': {'tags': ['search'], 'summary': "Détail d'un événement (_source Elasticsearch)", 'responses': {'200': _ok('Événement'), '404': _ERR}}},
            '/api/stats': {'get': {'tags': ['search'], 'summary': 'Statistiques du tableau de bord', 'responses': {'200': _ok('Statistiques', {'$ref': '#/components/schemas/Stats'})}}},
            '/api/overview': {'get': {'tags': ['dashboard'], 'summary': 'Centre de pilotage : KPI d’authentification comparés à la période précédente, IP prioritaires, santé (services, pipelines Logstash, fraîcheur, rejets)',
                'parameters': [{'name': 'period', 'in': 'query', 'schema': {'type': 'string', 'enum': ['24h', '7d', '30d', '90d']}, 'description': 'Par défaut : la période enregistrée de l’utilisateur.'}],
                'responses': {'200': _ok('Données du centre de pilotage'), '401': _ERR}}},
            '/api/dashboard/prefs': {
                'get': {'tags': ['dashboard'], 'summary': 'Blocs affichés et période du centre de pilotage (préférences de l’utilisateur)', 'responses': {'200': _ok('Préférences'), '401': _ERR}},
                'put': {'tags': ['dashboard'], 'summary': 'Enregistrer les blocs affichés et/ou la période',
                        'requestBody': {'required': True, 'content': {'application/json': {'schema': {'type': 'object', 'properties': {'widgets': {'type': 'object', 'additionalProperties': {'type': 'boolean'}, 'example': {'health': False}}, 'period': {'type': 'string', 'enum': ['24h', '7d', '30d', '90d']}}}}}},
                        'responses': {'200': _ok('Préférences enregistrées'), '400': _ERR, '401': _ERR}},
                'delete': {'tags': ['dashboard'], 'summary': 'Tout réafficher (réinitialiser)', 'responses': {'200': _ok('Préférences par défaut'), '401': _ERR}}},
            '/api/v1/logs': {'get': _search_op('Liste paginée des logs', 'v1')},
            '/api/v1/logs/{event_id}': {'parameters': [_ID], 'get': {'tags': ['v1'], 'summary': "Détail d'un log", 'responses': {'200': _ok('Événement'), '404': _ERR}}},
            '/api/v1/files': {'get': {'tags': ['v1'], 'summary': 'Fichiers importés', 'responses': {'200': _ok('Liste')}}},
            '/api/v1/stats': {'get': {'tags': ['v1'], 'summary': 'Statistiques globales', 'responses': {'200': _ok('Statistiques', {'$ref': '#/components/schemas/Stats'})}}},
        },
        'components': {
            'securitySchemes': {'sessionCookie': {'type': 'apiKey', 'in': 'cookie', 'name': 'sentinel_session'}},
            'schemas': {
                'Error': {'type': 'object', 'properties': {'error': {'type': 'string'}, 'message': {'type': 'string'}, 'details': {'type': 'array', 'items': {'type': 'string'}}}},
                'Hit': {'type': 'object', 'properties': {k: {'type': 'string', 'nullable': True} for k in
                        ('id', 'index', 'timestamp', 'level', 'service', 'ip', 'user', 'action', 'outcome', 'category', 'upload_id', 'time_mode', 'message')}},
                'SearchResult': {'type': 'object', 'properties': {'total': {'type': 'integer'}, 'total_exact': {'type': 'boolean'}, 'page': {'type': 'integer'},
                        'size': {'type': 'integer'}, 'pages': {'type': 'integer'}, 'took_ms': {'type': 'integer'}, 'cached': {'type': 'boolean'},
                        'hits': {'type': 'array', 'items': {'$ref': '#/components/schemas/Hit'}}}},
                'Stats': {'type': 'object', 'properties': {'total': {'type': 'integer'}, 'today': {'type': 'integer'}, 'errors': {'type': 'integer'}, 'uploads': {'type': 'integer'},
                        'levels': {'type': 'array', 'items': {'type': 'object'}}, 'services': {'type': 'array', 'items': {'type': 'object'}}, 'timeline': {'type': 'array', 'items': {'type': 'object'}}}},
            },
        },
    }
