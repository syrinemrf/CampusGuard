from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import app.main as app_module


@pytest.fixture
def dependency_doubles(monkeypatch):
    monkeypatch.setenv('ELASTICSEARCH_URL', 'http://es.test:9200')
    monkeypatch.setenv('MONGO_URI', 'mongodb://mongo.test:27017/')
    monkeypatch.setenv('REDIS_URL', 'redis://redis.test:6379/1')

    response = Mock(name='elasticsearch_response')
    response.json.return_value = {'status': 'yellow', 'timed_out': False}
    elasticsearch_get = Mock(name='elasticsearch_get', return_value=response)
    mongo_client = Mock(name='mongo_client')
    mongo_factory = Mock(name='mongo_factory', return_value=mongo_client)
    redis_client = Mock(name='redis_client')
    redis_factory = Mock(name='redis_factory', return_value=redis_client)

    monkeypatch.setattr(app_module.requests, 'get', elasticsearch_get)
    monkeypatch.setattr(app_module, 'MongoClient', mongo_factory)
    monkeypatch.setattr(app_module.Redis, 'from_url', redis_factory)

    return SimpleNamespace(
        response=response,
        elasticsearch_get=elasticsearch_get,
        mongo_client=mongo_client,
        mongo_factory=mongo_factory,
        redis_client=redis_client,
        redis_factory=redis_factory,
    )


@pytest.mark.parametrize('cluster_status', ['yellow', 'green'])
def test_ready_reports_all_dependencies_available(dependency_doubles, cluster_status):
    dependency_doubles.response.json.return_value = {
        'status': cluster_status,
        'timed_out': False,
    }

    with app_module.app.test_client() as client:
        response = client.get('/ready')

    assert response.status_code == 200
    assert response.get_json() == {
        'status': 'ready',
        'services': {
            'elasticsearch': 'ok',
            'mongodb': 'ok',
            'redis': 'ok',
        },
    }
    dependency_doubles.elasticsearch_get.assert_called_once_with(
        'http://es.test:9200/_cluster/health',
        params={
            'wait_for_status': 'yellow',
            'timeout': '2s',
            'master_timeout': '2s',
        },
        timeout=3,
    )
    dependency_doubles.response.raise_for_status.assert_called_once_with()
    dependency_doubles.response.json.assert_called_once_with()
    dependency_doubles.mongo_factory.assert_called_once_with(
        'mongodb://mongo.test:27017/', serverSelectionTimeoutMS=3000
    )
    dependency_doubles.mongo_client.admin.command.assert_called_once_with('ping')
    dependency_doubles.redis_factory.assert_called_once_with(
        'redis://redis.test:6379/1', socket_timeout=3
    )
    dependency_doubles.redis_client.ping.assert_called_once_with()
    dependency_doubles.mongo_client.close.assert_called_once_with()
    dependency_doubles.redis_client.close.assert_called_once_with()


@pytest.mark.parametrize(
    'cluster_health',
    [
        pytest.param({'status': 'red', 'timed_out': False}, id='red'),
        pytest.param({'status': 'yellow', 'timed_out': True}, id='timed-out'),
    ],
)
def test_ready_rejects_unhealthy_elasticsearch_cluster(
        dependency_doubles, cluster_health
):
    dependency_doubles.response.json.return_value = cluster_health

    with app_module.app.test_client() as client:
        response = client.get('/ready')

    assert response.status_code == 503
    assert response.get_json() == {
        'status': 'degraded',
        'services': {
            'elasticsearch': 'error',
            'mongodb': 'ok',
            'redis': 'ok',
        },
    }
    dependency_doubles.mongo_client.close.assert_called_once_with()
    dependency_doubles.redis_client.close.assert_called_once_with()


@pytest.mark.parametrize('failing_service', ['elasticsearch', 'mongodb', 'redis'])
def test_ready_reports_each_dependency_failure_and_closes_clients(
        dependency_doubles, failing_service
):
    if failing_service == 'elasticsearch':
        dependency_doubles.elasticsearch_get.side_effect = (
            app_module.requests.exceptions.Timeout('unavailable')
        )
    elif failing_service == 'mongodb':
        dependency_doubles.mongo_client.admin.command.side_effect = RuntimeError('unavailable')
    else:
        dependency_doubles.redis_client.ping.side_effect = RuntimeError('unavailable')

    with app_module.app.test_client() as client:
        response = client.get('/ready')

    expected_services = {
        'elasticsearch': 'ok',
        'mongodb': 'ok',
        'redis': 'ok',
    }
    expected_services[failing_service] = 'error'
    assert response.status_code == 503
    assert response.get_json() == {
        'status': 'degraded',
        'services': expected_services,
    }
    dependency_doubles.mongo_client.close.assert_called_once_with()
    dependency_doubles.redis_client.close.assert_called_once_with()
