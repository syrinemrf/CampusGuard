"""User accounts (MongoDB ``users``) and audit trail (``audit_actions``)."""
import logging
import secrets
from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from flask_login import UserMixin
from pymongo.errors import DuplicateKeyError
from werkzeug.security import check_password_hash, generate_password_hash

from app.security import ROLES

log = logging.getLogger('sentinel.users')
MIN_PASSWORD_LENGTH = 12
# Verified when the username does not exist, so the response time does not reveal valid accounts.
_DUMMY_HASH = generate_password_hash('dummy-password-for-timing-only')


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin):
    def __init__(self, doc):
        self.doc = doc

    @property
    def id(self):
        return str(self.doc['_id'])

    @property
    def username(self):
        return self.doc['username']

    @property
    def role(self):
        return self.doc['role']

    @property
    def is_active(self):
        return bool(self.doc.get('active', True))


class UserStore:
    def __init__(self, db):
        self.col = db.users

    def get(self, user_id):
        try:
            doc = self.col.find_one({'_id': ObjectId(user_id)})
        except (InvalidId, TypeError):
            return None
        return User(doc) if doc else None

    def by_username(self, username):
        doc = self.col.find_one({'username': username.strip().lower()})
        return User(doc) if doc else None

    def create(self, username, password, role):
        username = username.strip().lower()
        if not username or len(username) > 64 or not username.replace('_', '').replace('.', '').replace('-', '').isalnum():
            raise ValueError('Nom d’utilisateur invalide (lettres, chiffres, . _ - ; 64 max).')
        if role not in ROLES:
            raise ValueError(f'Rôle inconnu : {role}')
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f'Mot de passe trop court (minimum {MIN_PASSWORD_LENGTH} caractères).')
        if self.by_username(username):
            raise ValueError(f'L’utilisateur « {username} » existe déjà.')
        doc = {'username': username, 'password_hash': generate_password_hash(password), 'role': role,
               'active': True, 'created_at': utcnow(), 'last_login_at': None}
        try:
            doc['_id'] = self.col.insert_one(doc).inserted_id
        except DuplicateKeyError as exc:
            raise ValueError(f'L’utilisateur « {username} » existe déjà.') from exc
        return User(doc)

    def set_password(self, username, password):
        """Replace the password of an existing account (CLI only; the old one is not needed)."""
        if len(password or '') < MIN_PASSWORD_LENGTH:
            raise ValueError(f'Mot de passe trop court (minimum {MIN_PASSWORD_LENGTH} caractères).')
        result = self.col.update_one({'username': (username or '').strip().lower()},
                                     {'$set': {'password_hash': generate_password_hash(password)}})
        if result.matched_count != 1:
            raise ValueError(f'Compte « {username} » introuvable.')

    def authenticate(self, username, password):
        """Return the User for valid credentials of an active account, else None."""
        user = self.by_username(username or '')
        stored = user.doc['password_hash'] if user else _DUMMY_HASH
        ok = check_password_hash(stored, password or '')
        if user and ok and user.is_active:
            self.col.update_one({'_id': user.doc['_id']}, {'$set': {'last_login_at': utcnow()}})
            return user
        return None

    def seed(self, specs, environ):
        """Create default accounts ``[(username, role, env_var)]`` if missing.

        Returns ``[(username, role, password | None)]``; the password is returned only when it was
        generated here (printed once by the CLI, never stored in clear text)."""
        created = []
        for username, role, env_var in specs:
            if self.by_username(username):
                continue
            password = environ.get(env_var) or secrets.token_urlsafe(12)
            generated = not environ.get(env_var)
            self.create(username, password, role)
            created.append((username, role, password if generated else None))
        return created


def record_audit(db, actor, action, target=None, reason=None, details=None, ip=None):
    """Append an audit entry. Never raises: an audit failure is logged, not fatal to the request."""
    try:
        db.audit_actions.insert_one({
            'actor': actor, 'action': action, 'target': target, 'reason': reason,
            'details': details or {}, 'ip': ip, 'timestamp': utcnow()})
    except Exception:  # noqa: BLE001
        log.exception('audit write failed for action=%s', action)
