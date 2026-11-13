# HackBNB — Synthèse technique des vulnérabilités (D1-D4)

**Date d'investigation :** 9 et 11 novembre 2026
**Environnement testé :** pré-production (`https://hackbnb.dashbox.cloud`)
**Outils utilisés :** Burp Suite Community Edition (Repeater, Intruder)

Trace écrite des vulnérabilités identifiées dans le rapport de pentest (annexe 5), reproduites et prouvées en environnement de pré-production.

---

## D1 — Injection SQL sur `/api/rooms/`

| Champ | Valeur |
|---|---|
| **CWE** | CWE-89 (SQL Injection) |
| **OWASP Top 10** | A03:2021 – Injection |
| **Référence test** | OWASP WSTG-INPV-05 |
| **Localisation** | `back/api/rooms/rooms_api.py`, ligne 18 |

**Code vulnérable**
```python
if "category" in request.args:
    category = request.args["category"]
    rooms = Room.query.filter(text(f"category = '{category}'")).all()
```

**Mécanisme** : le paramètre `category` est concaténé directement dans une requête SQL brute (`sqlalchemy.text`) sans requête préparée ni paramètre bindé, permettant l'injection de clauses SQL arbitraires dans la condition `WHERE`.

### Preuve 1 — Bypass logique de la clause WHERE

Payload : `x' OR '1'='1'-- -`

| Requête | Réponse |
|---|---|
| ![requête bypass](img/D1_SQLi_1-bypass_req.png) | ![réponse bypass](img/D1_SQLi_1-bypass_res.png) |

`HTTP/2 200 OK`, `Content-Length: 3691` — 10 rooms renvoyées, alors qu'une catégorie inexistante (`x`) devrait renvoyer `[]` (liste vide). Preuve du contrôle de la logique SQL.

### Preuve 2 — Exfiltration de données hors périmètre (table `users`)

Payload : `x' UNION SELECT id, name, email, password_hash, 0, 0, 0, 0 FROM users-- -`

| Requête | Réponse |
|---|---|
| ![requête dump users](img/D1_SQLi_2-dump-users_req.png) | ![réponse dump users](img/D1_SQLi_2-dump-users_res.png) |

Les colonnes sélectionnées sont mappées positionnellement sur le modèle `Room` par l'ORM SQLAlchemy (`id→id`, `name→title`, `email→city`, `password_hash→price`). 3 comptes extraits :

| id | name | email | password_hash |
|---|---|---|---|
| 1 | John Doe | john@doe.com | XX *(valeur de seed, pas un hash réel — cf. note ci-dessous)* |
| 2 | test | test@test.com | 5f4dcc3b5aa765d61d8327deb882cf99 |
| 3 | Pain perdu vendredi ! | clubquisine@guardiaschool.fr | 86afb02a7da647a644c07deaccd233e6 |

*Note : le compte `John Doe` est initialisé dans `database/seed.py` avec `password_hash="XX"` en dur (donnée de démo, pas un hash MD5 valide) — seuls les comptes 2 et 3 illustrent le problème réel de hachage MD5 non salé.*

**Impact** : compromission totale de la base de données (lecture arbitraire de toute table via UNION SELECT), incluant les comptes utilisateurs et leurs hash de mot de passe.

**Niveau de risque (échelle ANSSI)** : Exploitation **Facile** × Impact **Critique** = **Critique** (conforme à l'évaluation du rapport de pentest, annexe 5, item D1).

**Recommandation** : remplacer la requête SQL brute par l'ORM standard (`Room.query.filter_by(category=category)`) ou par une requête paramétrée bindée (`text("category = :cat").bindparams(cat=category)`). Cf. OWASP SQL Injection Prevention Cheat Sheet.

**Observation complémentaire (hors périmètre D1-D8, à ajouter aux recommandations finales)** : les hash extraits font 32 caractères hexadécimaux → format **MD5**, algorithme de hachage obsolète et non salé (`5f4dcc3b5aa765d61d8327deb882cf99` = MD5 connu de `"password"`). Recommandation : migrer vers bcrypt/argon2 avec sel.

---

## D2 — Path Traversal sur `/api/uploads/`

| Champ | Valeur |
|---|---|
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| **OWASP Top 10** | A01:2021 – Broken Access Control |
| **Référence test** | OWASP WSTG-ATHZ-01 (Testing Directory Traversal File Include) |
| **Localisation** | `back/api/uploads/uploads_api.py`, ligne 7 |

**Code vulnérable**
```python
@uploads_api.route('/')
def get_upload():
   return send_file('uploads/' + request.args.get("name"))
```

**Mécanisme** : le paramètre `name` est concaténé directement à un chemin de base (`uploads/`) sans filtrage des séquences `../`, permettant de sortir du répertoire prévu.

### Preuve 1 — Lecture du code source applicatif

Payload : `../app.py`

| Requête | Réponse |
|---|---|
| ![requête lecture source](img/D2_PathTraversal_1-read-source_req.png) | ![réponse lecture source](img/D2_PathTraversal_1-read-source_res.png) |

`HTTP/2 200 OK`, `Content-Type: text/x-python`, `Content-Disposition: inline; filename=app.py` — code source complet de `back/app.py` renvoyé en clair.

### Preuve 2 — Lecture fichier système (hors périmètre applicatif)

Payload : `../../../../../etc/passwd`

| Requête | Réponse |
|---|---|
| ![requête lecture /etc/passwd](img/D2_PathTraversal_2-read-etc-passwd_req.png) | ![réponse lecture /etc/passwd](img/D2_PathTraversal_2-read-etc-passwd_res.png) |

`HTTP/2 200 OK`, `Content-Type: application/octet-stream`, `Content-Disposition: inline; filename=passwd` — fichier système `/etc/passwd` renvoyé en clair. Preuve que la faille dépasse largement le périmètre applicatif (accès au système de fichiers du serveur/conteneur).

**Impact** : lecture arbitraire de tout fichier accessible par le process Flask (code source, configuration, fichiers système), bien au-delà du répertoire `uploads/` prévu.

**Niveau de risque (échelle ANSSI)** : Exploitation **Facile** × Impact **Critique** = **Critique** (conforme annexe 5, item D2).

**Recommandation** : valider/assainir le paramètre `name` (whitelist de caractères, `os.path.basename()`), et vérifier via `os.path.realpath()` que le chemin résolu reste bien dans le répertoire `uploads/`.

---

## D3 — SSRF sur `/api/bookings/<reference>/checkout-lines`

| Champ | Valeur |
|---|---|
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **OWASP Top 10** | A10:2021 – Server-Side Request Forgery |
| **Localisation** | `back/services/stripe.py`, lignes 31-36 + `back/api/bookings/bookings_api.py`, ligne 44 |

**Code vulnérable**
```python
# bookings_api.py
checkout_session_id = request.args.get("checkout_session_id")  # non contrôlé
return jsonify(get_checkout_lines(checkout_session_id))

# stripe.py
def get_checkout_lines(checkout_session_id):
    url = f"https://api.stripe.com/v1/checkout/sessions/{checkout_session_id}/line_items"
    session = requests.Session()
    session.auth = (os.getenv('STRIPE_API_KEY'), "")  # clé secrète du serveur
    return session.get(url).json()["data"]
```

**Mécanisme** : le paramètre `checkout_session_id` est injecté tel quel dans l'URL interrogée auprès de l'API Stripe, authentifiée avec la clé secrète du marchand. En injectant une séquence `../../` suivie d'un `#` (pour tronquer le `/line_items` final), on détourne la requête vers n'importe quel endpoint Stripe (condition : la réservation utilisée doit être payée, sinon `422`).

### Preuve — Détournement vers un endpoint liste (fuite cross-clients)

Réservation utilisée : `57TDGUK1` (`is_paid: true`)
Payload : `checkout_session_id=../../checkout/sessions%23`

| Requête | Réponse |
|---|---|
| ![requête SSRF](img/D3_SSRF_1-list-all-sessions_req.png) | ![réponse SSRF](img/D3_SSRF_1-list-all-sessions_res.png) |

`HTTP/2 200 OK` — la réponse contient les sessions de paiement Stripe de **tous les clients**, pas seulement celles liées à la réservation `57TDGUK1`.

**Finding critique additionnel** : une des sessions retournées expose, dans son champ `success_url`, le `checkout_confirmation_secret` **en clair** d'une autre réservation (`VM4UXB28`, `payment_status: "unpaid"`) :
```
https://hackbnb.dashbox.cloud/booking/VM4UXB28?checkout_confirmation_secret=2cac7e5ac3ef2115fc18c06bbc5cdbeac325c1966f50184f0ed7b7e3ad1d61c265220cc0eaf9c9933de7883324d8efdd008ad8fe79a9624c818a802a8933f1c5
```
→ **chaînage direct D3 → D4** : cette SSRF permet de récupérer le secret de confirmation de *n'importe quelle* réservation d'*un autre client*, sans avoir besoin de le bruteforcer (cf. D4). C'est un vecteur d'exploitation encore plus efficace que le bruteforce décrit dans le rapport de pentest pour D4.

**Impact** : exposition de données de paiement et de secrets de confirmation appartenant à d'autres clients, via une requête authentifiée avec la clé API du marchand détournée vers un périmètre non prévu par l'application.

**Niveau de risque (échelle ANSSI)** : Exploitation **Modérée** × Impact **Critique** = **Critique** (conforme annexe 5, item D3).

**Recommandation** : valider `checkout_session_id` contre un format strict (regex `^cs_[a-zA-Z0-9_]+$`), et/ou vérifier que la session Stripe récupérée correspond bien au `stripe_checkout_session_id` déjà enregistré pour la réservation concernée.

---

## D4 — Génération vulnérable du secret de confirmation de paiement

| Champ | Valeur |
|---|---|
| **CWE** | CWE-330 (Use of Insufficiently Random Values) |
| **OWASP Top 10** | A02:2021 – Cryptographic Failures |
| **Localisation** | `back/api/bookings/bookings_api.py`, lignes 93-95 |

**Code vulnérable**
```python
random_string = str(int(time.time()))  # timestamp UNIX à la seconde près
checkout_confirmation_secret = hashlib.sha512(random_string.encode('utf-8')).hexdigest()
```

**Mécanisme** : le secret de confirmation de paiement n'est qu'un hash SHA-512 du timestamp serveur (en secondes). Un attaquant connaissant l'heure approximative de création d'une réservation (via le header `Date` de la réponse HTTP, par exemple) peut bruteforcer ce secret en quelques dizaines/centaines de tentatives, et confirmer le paiement d'une réservation **sans jamais payer**.

**Méthodologie** : Burp Intruder, payload type `Numbers` (plage ciblée autour du timestamp de création, pas de l'heure courante — le secret est fixé au moment de la création et ne change pas), règle de traitement `Hash → SHA-512` appliquée au payload, position marquée sur la valeur de `confirmationSecret` dans le corps JSON de `POST /bookings/<reference>/confirm-checkout`.

### Preuve — Bruteforce réussi

Réservation créée : `XFX6Q5I2` (sans jamais ouvrir le `checkout_url` ni effectuer de paiement réel)
Fenêtre testée : timestamp centre (± marge) autour de l'heure de création — secret retrouvé exactement au timestamp `1794408723` (= heure de création exacte, aucun décalage)

| Requête | Réponse |
|---|---|
| ![requête bruteforce réussi](img/D4_WeakSecret_1-bruteforce-success_req.png) | ![réponse bruteforce réussi](img/D4_WeakSecret_1-bruteforce-success_res.png) |

Le tableau de résultats Intruder montre la requête #91 en `200 OK` (longueur de réponse 166, `{"success": true}`), distincte des dizaines de tentatives en `422` (longueur 207) juste au-dessus.

### Preuve — Confirmation sans paiement réel

```
GET /api/bookings/XFX6Q5I2 HTTP/2
```

| Requête | Réponse |
|---|---|
| ![requête vérification paiement](img/D4_WeakSecret_2-booking-confirmed-unpaid_req.png) | ![réponse vérification paiement](img/D4_WeakSecret_2-booking-confirmed-unpaid_res.png) |

`"is_paid": true` — la réservation de 340€ (`room-1`, 2 nuits) est confirmée comme payée, sans qu'aucun paiement Stripe réel n'ait été effectué (le `checkout_url` n'a jamais été ouvert).

**Impact** : contournement complet du paiement — confirmation arbitraire de n'importe quelle réservation sans transaction financière réelle.

**Niveau de risque (échelle ANSSI)** : Exploitation **Modérée** × Impact **Critique** = **Critique** (conforme annexe 5, item D4).

**Recommandation** : générer le secret avec une source d'aléa cryptographiquement sûre (`secrets.token_hex(32)` en Python), indépendante de toute information prévisible comme un timestamp.

**Observation complémentaire** : combiné à D3 (SSRF), ce secret peut aussi être lu directement dans le `success_url` d'une session Stripe d'un autre client (cf. finding D3), rendant le bruteforce ci-dessus même superflu pour un attaquant qui aurait déjà exploité D3.
