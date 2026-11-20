"""Trafic SSH légitime d'un campus, au format syslog sshd, sur la même plage horaire que le journal réel LabSZ.

Le journal Loghub ne contient presque que des attaques : pour mesurer les fausses alertes, il faut du trafic normal.
Ce générateur (graine fixe, reproductible) produit des étudiants et personnels qui se connectent, se trompent parfois
de mot de passe, oublient un mot de passe, et un serveur de sauvegarde qui se connecte toutes les deux minutes.
Ces deux derniers profils sont les cas difficiles : ils ressemblent à une attaque sans en être une.
"""
import random
from datetime import datetime, timedelta

START = datetime(2015, 12, 10, 6, 55, 0)
END = datetime(2015, 12, 10, 11, 5, 0)
PREFIXES = ('41.230', '41.226', '197.0', '197.14', '102.157', '102.158', '196.203')     # opérateurs tunisiens


def generate(seed=2026, users=90):
    rng = random.Random(seed)
    lines, pid = [], 30000

    def emit(t, p, msg):
        lines.append((t, f"{t:%b} {t.day:2d} {t:%H:%M:%S} LabSZ sshd[{p}]: {msg}"))

    def session(t, user, ip, fails=0, success=True, method='password'):
        nonlocal pid
        pid += rng.randint(3, 40)
        port = rng.randint(30000, 65000)
        for _ in range(fails):
            emit(t, pid, f'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}')
            t += timedelta(seconds=rng.randint(2, 6))
            emit(t, pid, f'Failed password for {user} from {ip} port {port} ssh2')
            t += timedelta(seconds=rng.randint(3, 15))
        if not success:
            emit(t, pid, f'Connection closed by {ip} [preauth]')
            return
        emit(t, pid, f'Accepted {method} for {user} from {ip} port {port} ssh2')
        emit(t, pid, f'pam_unix(sshd:session): session opened for user {user} by (uid=0)')
        end = t + timedelta(minutes=rng.choice([1, 3, 8, 15, 30, 45]))
        emit(end, pid + 1, f'Received disconnect from {ip}: 11: disconnected by user')
        emit(end, pid, f'pam_unix(sshd:session): session closed for user {user}')

    span = (END - START).total_seconds()
    labels = {}
    for u in range(users):
        name = rng.choice(['etu', 'ens', 'adm']) + f'{u:03d}'
        ip = f'{rng.choice(PREFIXES)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}'
        labels[ip] = 'normal'
        for _ in range(rng.choice([1, 1, 2, 2, 3, 4])):
            t = START + timedelta(seconds=rng.uniform(0, span - 3600))
            r = rng.random()
            if r < 0.80:
                session(t, name, ip)
            elif r < 0.95:
                session(t, name, ip, fails=rng.choice([1, 1, 2]))
            else:                                                       # mot de passe oublié : cas difficile
                session(t, name, ip, fails=rng.choice([3, 4, 6]), success=rng.random() < 0.5)
    backup = '102.157.20.5'                                             # automate de sauvegarde : cas difficile
    labels[backup] = 'normal'
    t = START
    while t < END:
        session(t, 'backup', backup, method='publickey')
        t += timedelta(minutes=2)
    return [line for _, line in sorted(lines)], labels


if __name__ == '__main__':
    out, labels = generate()
    print('\n'.join(out[:12]))
    print(len(out), 'lignes,', len(labels), 'IP légitimes')
