"""Test de charge (S6, module K du sujet) : 100 utilisateurs simultanés sur l'application réelle.

    pip install locust==2.37.10
    set SENTINEL_PASSWORD=...            (PowerShell : $env:SENTINEL_PASSWORD="...")
    locust -f tests/perf/locustfile.py --host http://localhost:8000 --headless -u 100 -r 10 -t 3m \
           --csv docs/evidence/load --html docs/evidence/load_report.html

Chaque utilisateur virtuel se connecte une fois (compte analyste, API JSON), puis enchaîne ce que fait un analyste :
ouvrir le centre de pilotage, chercher dans les logs (filtres, texte libre, Lucene), regarder les alertes, ouvrir un
événement. Les pondérations reflètent cet usage. La limitation de débit par utilisateur (300 req/min) est désactivée
pendant le test en lançant l'application avec API_RATE_LIMIT_PER_MIN=0, sinon on mesure le limiteur et pas l'application.
"""
import os
import random

from locust import HttpUser, between, task

USER = os.getenv('SENTINEL_USER', 'analyste')
PASSWORD = os.getenv('SENTINEL_PASSWORD', '')
TERMS = ['Failed password', 'Invalid user', 'root', 'admin', 'preauth', 'Accepted', 'disconnect']
IPS = ['183.62.75.200', '187.141.25.159', '103.99.89.9', '5.188.1.6', '203.0.113.50']


class Analyst(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        r = self.client.post('/api/auth/login', json={'username': USER, 'password': PASSWORD}, name='connexion')
        if r.status_code != 200:
            raise RuntimeError(f'connexion impossible (HTTP {r.status_code}) : définir SENTINEL_PASSWORD')
        self.client.headers['X-CSRF-Token'] = r.json()['csrf_token']
        self.event_ids = []

    @task(3)
    def home(self):
        self.client.get('/', name='page accueil')

    @task(2)
    def overview(self):
        self.client.get('/api/overview', params={'period': random.choice(['24h', '7d', '30d'])}, name='/api/overview')

    @task(6)
    def search(self):
        kind = random.random()
        if kind < 0.4:
            params = {'q': random.choice(TERMS)}
        elif kind < 0.7:
            params = {'ip': random.choice(IPS), 'outcome': 'failure'}
        else:
            params = {'query': f'event.outcome:failure AND user.name:{random.choice(["root", "admin", "oracle"])}'}
        params['nocache'] = '1' if random.random() < 0.3 else '0'
        params['record'] = '0'
        r = self.client.get('/api/search', params=params, name='/api/search')
        if r.ok:
            self.event_ids = [h['id'] for h in r.json().get('hits', [])[:5] if 'id' in h] or self.event_ids

    @task(2)
    def event(self):
        if self.event_ids:
            self.client.get(f'/api/events/{random.choice(self.event_ids)}', name='/api/events/[id]')

    @task(3)
    def alerts(self):
        self.client.get('/api/alerts/summary', name='/api/alerts/summary')

    @task(1)
    def alerts_page(self):
        self.client.get('/alerts', name='page alertes')

    @task(1)
    def facets(self):
        self.client.get('/api/search/facets', name='/api/search/facets')
