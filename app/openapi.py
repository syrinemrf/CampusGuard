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
    {'name': 'query', 'in': 'query', 'schema': {'type': 'string', 'maxLength': 1000},
     'description': 'Requête avancée en syntaxe Lucene (query_string, comme la barre Kibana), combinée aux filtres. Ex. event.outcome:failure AND NOT user.name:admin'},
    {'name': 'dsl', 'in': 'query', 'schema': {'type': 'string', 'maxLength': 4000},
     'description': 'Requête avancée en Query DSL Elasticsearch (JSON d’une clause, ou {"query": …}). Clauses autorisées : bool, term(s), match, range, exists, wildcard, regexp, prefix, query_string… ; scripts et recherches dans d’autres index refusés.'},
    {'name': 'sort_by', 'in': 'query', 'schema': {'type': 'string', 'enum': ['timestamp', 'level', 'service'], 'default': 'timestamp'}},
    {'name': 'sort', 'in': 'query', 'schema': {'type': 'string', 'enum': ['asc', 'desc'], 'default': 'desc'}},
    {'name': 'page', 'in': 'query', 'schema': {'type': 'integer', 'minimum': 1, 'default': 1}},
    {'name': 'size', 'in': 'query', 'schema': {'type': 'integer', 'minimum': 1, 'maximum': 100, 'default': 50}},
]
_ID = {'name': 'event_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}
_UPLOAD_ID = {'name': 'upload_id', 'in': 'path', 'required': True, 'schema': {'type': 'string', 'pattern': '^[0-9a-f]{32}$'}}
_ALERT = {'name': 'alert_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}
_RULE = {'name': 'rule_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}
_RULE_BODY = {'required': True, 'content': {'application/json': {'schema': {'type': 'object', 'required': ['id', 'name', 'type', 'window', 'severity'],
    'properties': {'id': {'type': 'string', 'example': 'brute-force-ip'}, 'name': {'type': 'string'}, 'description': {'type': 'string'},
                   'type': {'type': 'string', 'enum': ['threshold', 'cardinality', 'pattern', 'silence']},
                   'query': {'type': 'string', 'description': 'query_string Elasticsearch (syntaxe Lucene, comme la barre Kibana)', 'example': 'event.outcome:failure'},
                   'window': {'type': 'string', 'enum': ['5m', '15m', '1h', '24h']}, 'severity': {'type': 'string', 'enum': ['low', 'medium', 'high', 'critical']},
                   'group_by': {'type': 'string', 'enum': ['', 'source.ip', 'user.name', 'service.name']}, 'threshold': {'type': 'integer', 'minimum': 1},
                   'distinct_field': {'type': 'string', 'enum': ['user.name', 'source.ip', 'service.name']}, 'pattern': {'type': 'string'},
                   'outside_hours': {'type': 'array', 'items': {'type': 'integer'}, 'example': [7, 20]},
                   'cooldown_minutes': {'type': 'integer', 'minimum': 0, 'maximum': 1440}, 'enabled': {'type': 'boolean'},
                   'actions': {'type': 'object', 'properties': {'email': {'type': 'boolean'}, 'webhook': {'type': 'boolean'}, 'block_ip': {'type': 'boolean'}}}}}}}}
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
        'info': {'title': 'CampusGuard / Sentinel API', 'version': '3.0.0',
                 'description': ("API REST du laboratoire CampusGuard. Authentification par cookie de session (POST /api/auth/login) ; "
                                 "les requêtes POST/DELETE exigent l'en-tête X-CSRF-Token renvoyé à la connexion. "
                                 "Limite : 300 requêtes/minute et par utilisateur (HTTP 429).")},
        'servers': [{'url': '/'}],
        'tags': [{'name': 'auth'}, {'name': 'uploads'}, {'name': 'search'}, {'name': 'dashboard'},
                 {'name': 'alerts', 'description': 'S4 — alertes, incidents, règles (éditeur + test), blocage d’IP.'}, {'name': 'v1', 'description': 'Alias stables /api/v1 du sujet (logs, files, stats).'}],
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
            '/api/alerts': {'get': {'tags': ['alerts'], 'summary': 'Liste des alertes',
                'parameters': [{'name': 'status', 'in': 'query', 'schema': {'type': 'string', 'enum': ['active', 'open', 'acknowledged', 'resolved']}},
                               {'name': 'severity', 'in': 'query', 'schema': {'type': 'string', 'enum': ['low', 'medium', 'high', 'critical']}},
                               {'name': 'rule', 'in': 'query', 'schema': {'type': 'string'}},
                               {'name': 'limit', 'in': 'query', 'schema': {'type': 'integer', 'default': 50, 'maximum': 200}}],
                'responses': {'200': _ok('Alertes'), '401': _ERR}}},
            '/api/alerts/summary': {'get': {'tags': ['alerts'], 'summary': 'Résumé interrogé périodiquement (badge, titre de l’onglet, notification du navigateur)', 'responses': {'200': _ok('Résumé')}}},
            '/api/alerts/stats': {'get': {'tags': ['alerts'], 'summary': 'Statistiques : alertes par jour, top 10 des règles, MTTR, ouvertes par gravité',
                'parameters': [{'name': 'days', 'in': 'query', 'schema': {'type': 'integer', 'default': 14, 'maximum': 90}}], 'responses': {'200': _ok('Statistiques')}}},
            '/api/alerts/{alert_id}': {'parameters': [_ALERT], 'get': {'tags': ['alerts'], 'summary': "Détail d'une alerte (historique, notifications, réponse)", 'responses': {'200': _ok('Alerte'), '404': _ERR}}},
            '/api/alerts/{alert_id}/{action}': {'parameters': [_ALERT, {'name': 'action', 'in': 'path', 'required': True, 'schema': {'type': 'string', 'enum': ['acknowledge', 'resolve']}}],
                'post': {'tags': ['alerts'], 'summary': 'Prendre en compte ou résoudre (admin, analyste)',
                         'requestBody': {'content': {'application/json': {'schema': {'type': 'object', 'properties': {'note': {'type': 'string', 'maxLength': 500}}}}}},
                         'responses': {'200': _ok('Alerte mise à jour'), '403': _ERR, '404': _ERR, '409': _ERR}}},
            '/api/alerts/run': {'post': {'tags': ['alerts'], 'summary': 'Évaluer les règles maintenant (admin, démonstration)', 'responses': {'200': _ok('Résumé du cycle'), '409': _ERR}}},
            '/api/alerts/rules': {
                'get': {'tags': ['alerts'], 'summary': 'Règles d’alerte', 'responses': {'200': _ok('Règles')}},
                'post': {'tags': ['alerts'], 'summary': 'Créer une règle (admin)', 'requestBody': _RULE_BODY, 'responses': {'201': _ok('Règle'), '400': _ERR, '403': _ERR}}},
            '/api/alerts/rules/test': {'post': {'tags': ['alerts'], 'summary': 'Tester une règle sans l’enregistrer : groupes qui déclencheraient + requête Elasticsearch',
                'requestBody': _RULE_BODY, 'responses': {'200': _ok('Résultat du test'), '400': _ERR}}},
            '/api/alerts/rules/{rule_id}': {'parameters': [_RULE],
                'put': {'tags': ['alerts'], 'summary': 'Modifier une règle (admin)', 'requestBody': _RULE_BODY, 'responses': {'200': _ok('Règle'), '400': _ERR, '404': _ERR}},
                'delete': {'tags': ['alerts'], 'summary': 'Supprimer une règle (admin)', 'responses': {'200': _ok('Supprimée'), '404': _ERR}}},
            '/api/alerts/rules/{rule_id}/enabled': {'parameters': [_RULE], 'post': {'tags': ['alerts'], 'summary': 'Activer / désactiver une règle (admin)',
                'requestBody': {'content': {'application/json': {'schema': {'type': 'object', 'properties': {'enabled': {'type': 'boolean'}}}}}}, 'responses': {'200': _ok('Règle')}}},
            '/api/blocklist': {
                'get': {'tags': ['alerts'], 'summary': 'IP bloquées (actives, durée restante) et historique', 'responses': {'200': _ok('Liste')}},
                'post': {'tags': ['alerts'], 'summary': 'Bloquer une IP pour une durée (admin) — effet local uniquement',
                         'requestBody': {'required': True, 'content': {'application/json': {'schema': {'type': 'object', 'required': ['ip'],
                             'properties': {'ip': {'type': 'string'}, 'minutes': {'type': 'integer', 'minimum': 1, 'maximum': 1440}, 'reason': {'type': 'string'}}}}}},
                         'responses': {'201': _ok('Bloquée'), '400': _ERR, '403': _ERR}}},
            '/api/blocklist/{ip}': {'parameters': [{'name': 'ip', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}],
                'delete': {'tags': ['alerts'], 'summary': 'Débloquer une IP (admin)', 'responses': {'200': _ok('Débloquée'), '404': _ERR}}},
            '/api/notifications/demo': {'get': {'tags': ['alerts'], 'summary': 'Derniers webhooks reçus par le récepteur de démonstration', 'responses': {'200': _ok('Webhooks')}}},
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
                        'es_query': {'type': 'object', 'description': 'Requête Elasticsearch réellement exécutée (filtres + requête avancée)'},
                        'hits': {'type': 'array', 'items': {'$ref': '#/components/schemas/Hit'}}}},
                'Stats': {'type': 'object', 'properties': {'total': {'type': 'integer'}, 'today': {'type': 'integer'}, 'errors': {'type': 'integer'}, 'uploads': {'type': 'integer'},
                        'levels': {'type': 'array', 'items': {'type': 'object'}}, 'services': {'type': 'array', 'items': {'type': 'object'}}, 'timeline': {'type': 'array', 'items': {'type': 'object'}}}},
            },
        },
    }
