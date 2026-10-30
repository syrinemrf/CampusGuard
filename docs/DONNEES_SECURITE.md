# Jeu de données de sécurité — stratégie reproductible

## Sources et usages
1. **Loghub OpenSSH** : authentique journal d'authentification SSH de l'archive publique `logpai/loghub`, répertoire `OpenSSH/` ; `OpenSSH_2k.log` sert aux premiers tests. Des lignes représentent des événements réels, mais **ne possèdent pas de vérité terrain d'attaque** : ne pas les présenter comme labels supervisés. Certaines années ne sont pas présentes dans les lignes source : l'année 2026 utilisée lors du replay est une hypothèse technique de démonstration, pas une date historique authentifiée.
2. **Simulateur** : données **totalement synthétiques** en CSV pare-feu et JSONL authentification, avec `labels.ground_truth` uniquement pour les scénarios construits. Adresse IP de documentation RFC 5737 et utilisateurs fictifs.
3. **Cowrie** : source temps réel facultative sur VPS isolé, hors S1 ; ne jamais exposer une machine personnelle ou universitaire sur Internet.

## Préparation
Télécharger depuis le dépôt officiel GitHub (ou via `python scripts/prepare_openssh.py --download`), conserver l'original hors Git sous `datasets/raw/`, et transformer une sélection représentative en JSONL proche d'ECS via le même script. Les adresses IP originales sont pseudonymisées dans les exports de démonstration ; les noms d'utilisateur sont également pseudonymisés. Décrire les catégories d'échecs, succès et événements inconnus sans fabriquer de vérité terrain.

Commande : `python scripts/prepare_openssh.py --download --limit 2000`.

## Contrôles de qualité
- Tracer la source, la date d'accès et le hash SHA-256 de l'original ; produire le nombre de lignes lues et d'événements interprétés.
- Champs requis : `@timestamp` UTC construit pour le replay, `service.name`, `log.level`, `event.category`, `event.action`, `event.outcome`, `message`.
- Conserver la ligne originale seulement dans le dossier local hors Git ; l'export utilisé pour l'application ne doit pas exposer les IP ou utilisateurs originaux.
- Un taux d'événements non interprétés doit être fourni sans inventer de catégories.
