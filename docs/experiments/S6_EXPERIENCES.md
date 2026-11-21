# S6 — Expériences : règles vs Isolation Forest, TF-IDF vs MiniLM

Reproduire : `pip install -r requirements-ml.txt` puis `python experiments/run_s6.py`
(résultats bruts : `s6_results.json`, figures : `s6_anomaly.png`, `s6_templates.png`).

## Données

- **Attaques réelles** : journal sshd du serveur LabSZ (Loghub OpenSSH_2k, 2 000 lignes, 10 décembre 2015, 4 h 08).
  29 adresses attaquantes. Une seule session légitime (119.137.62.142, compte qui s'est réellement connecté).
- **Trafic légitime** : 92 adresses d'un campus simulé (`experiments/campus_benign.py`, graine fixe) sur la même plage
  horaire et au même format : connexions normales, fautes de frappe, mots de passe oubliés (jusqu'à 6 échecs),
  et un serveur de sauvegarde qui se connecte toutes les 2 minutes.
- Le journal Loghub ne contient presque que des attaques ; sans trafic légitime on ne pourrait pas compter les fausses alertes.

## 1. Règles du worker vs Isolation Forest

Unité : une adresse IP sur une fenêtre de 5 minutes (442 fenêtres, dont 50 d'attaque). Neuf caractéristiques par
fenêtre : volume, échecs, réussites, comptes inexistants, comptes distincts, tentatives sur root, part d'échecs,
coupures avant authentification, présence répétée. Isolation Forest apprend sur **une autre journée** de trafic
normal, puis surveille : c'est l'usage réel (apprendre l'habituel, signaler l'inhabituel).

| Méthode | Précision | Rappel | F1 | IP attaquantes trouvées | IP légitimes signalées |
|---|---|---|---|---|---|
| Règles (5 échecs ou 5 comptes en 5 min) | 0,80 | 0,32 | 0,46 | 10 / 29 | 4 / 92 |
| Isolation Forest (seuil 1 %) | 0,77 | 0,78 | 0,77 | 24 / 29 | 11 / 92 |

Précision moyenne d'Isolation Forest sur toute la courbe (AP) : 0,66.

**Ce que les règles ne voient pas.** 19 des 29 adresses attaquantes ne dépassent jamais 5 échecs en 5 minutes :
une ou deux tentatives par passage, parfois réparties sur plusieurs fenêtres (52.80.34.196 : 5 échecs étalés sur
5 fenêtres), ou des sondages sans mot de passe. Isolation Forest les isole par leur profil — un compte inexistant,
une coupure avant authentification, aucune réussite — et l'explique, par exemple pour 173.234.31.186 :
« coupures avant authentification (2), mots de passe refusés (1), part d'échecs (1) ».

**Ce qui le trompe.** Les étudiants qui oublient leur mot de passe (4 à 6 échecs d'affilée) : leur profil ressemble
à une petite force brute. La règle de seuil se trompe aussi sur les 6 échecs.

**Décision retenue dans l'application.** Les deux méthodes ont des rôles différents :
- les **règles** déclenchent la réponse immédiate (blocage de l'IP) parce que leurs alertes sont presque toujours justes ;
- **Isolation Forest** devient une règle « Comportement SSH anormal » de gravité moyenne, **sans blocage**, qui
  propose à l'analyste les attaques lentes avec leurs causes probables (`app/ml/online.py`, type de règle `anomaly`).
  Le worker réapprend à chaque cycle sur les 7 derniers jours, en écartant les fenêtres déjà signalées par les règles.

## 2. Regrouper les messages par type : TF-IDF vs MiniLM

Vérité terrain : les types d'événements annotés par Loghub (`OpenSSH_2k.log_structured.csv`). Le seuil de distance
est réglé sur les 1 000 premiers messages et appliqué tel quel aux 1 000 suivants (14 types présents).

| Méthode | GA | ARI | NMI | Groupes | Temps (1 000 messages) |
|---|---|---|---|---|---|
| TF-IDF, message brut | 0,34 | 0,95 | 0,90 | 41 | 0,02 s |
| TF-IDF, message masqué | 0,69 | 0,96 | 0,97 | 14 | 0,02 s |
| MiniLM, message brut | 0,34 | 0,96 | 0,92 | 54 | 12 s |
| MiniLM, message masqué | 0,69 | 0,96 | 0,97 | 13 | 13 s |
| Drain3 (analyseur de logs de référence) | 1,00 | 1,00 | 1,00 | 14 | 0,01 s |

GA (grouping accuracy, mesure du benchmark Loghub) : part des messages dont le groupe est exactement un type réel.
« Masqué » : IP, ports, nombres, noms d'hôtes et comptes remplacés par un jeton avant de comparer.

- **Le masquage compte plus que le modèle** : il double la GA pour les deux représentations.
- **MiniLM n'apporte rien sur des logs sshd** : messages très codifiés, peu de vocabulaire ; il demande plus de 500 fois plus
  de temps et un modèle de 87 Mo. Il serait utile sur des messages rédigés librement (applications métier).
- L'écart restant (GA 0,69) vient d'un seul cas : « authentication failure … rhost=<IP> » et la même ligne suivie
  de « user=root » sont deux types pour Loghub, un seul pour un regroupement par similarité.
- **Drain3**, algorithme d'analyse de logs fondé sur la structure des messages, retrouve exactement les 14 types.

**Nouveaux types de messages** (10 tirages, 3 types retirés de l'apprentissage à chaque fois) : TF-IDF masqué
précision 0,98, rappel 0,59 ; MiniLM masqué précision 0,97, rappel 0,53. Quand un message est signalé « nouveau »,
c'est presque toujours vrai ; environ 4 sur 10 passent inaperçus parce qu'ils ressemblent à un type connu.

**Décision retenue.** Masquage + TF-IDF (ou Drain3) pour compter les types de messages et signaler les nouveaux ;
MiniLM n'est pas intégré à l'application.

## Limites

- Le trafic légitime est simulé : les taux de fausses alertes dépendent de ce profil de campus.
- Un seul serveur, quatre heures : les résultats indiquent des tendances, pas des performances garanties.
- MiniLM : modèle all-MiniLM-L6-v2 exporté en ONNX (Xenova), empreinte SHA-256 vérifiée
  `759c3cd2b7fe7e93933ad23c4c9181b7396442a2ed746ec7c1d46192c469c46e`, exécuté sans PyTorch.
