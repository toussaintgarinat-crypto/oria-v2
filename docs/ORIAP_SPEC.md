# OriaP — Spécification v0.1 (brouillon)

Protocole d'identité et d'appariement d'Oria. Implémentation de référence (PoC) : `oriap/`.

## 1. Identité
- Paire de clés **Ed25519** générée localement. Aucun enregistrement central.
- **ID Oria** = `oria:` + base32 minuscule (sans padding) de la clé publique de 32 octets.
- Remplace le numéro de téléphone. La graine privée (32 octets) ne quitte jamais le nœud.
- Hors périmètre v0.1 : rotation/révocation de clé, pseudonymes lisibles, multi-appareils.

## 2. Handshake mutuel (3 messages, JSON canonique : clés triées, sans espaces)
| Msg | Sens | Contenu |
|---|---|---|
| hello1 | A→B | `v`, `id`, `eph` (X25519 hex), `nonce` (16 o hex), `ts` (epoch s) |
| hello2 | B→A | idem pour B + `sig` = Sign_B(`"oriap/v1/handshake"` ‖ hello1 ‖ hello2 sans sig) |
| auth | A→B | `sig` = Sign_A(`"oriap/v1/handshake"` ‖ hello1 ‖ hello2 sans sig ‖ `"A"`) |

Règles : version = 1 ; `ts` à ±120 s ; si l'ID attendu du pair est connu (scan QR, lien, annuaire), il doit correspondre ; toute signature invalide ferme la session.

## 3. Clé de session
`HKDF-SHA256(X25519(eph_a, eph_b), salt = nonce_a ‖ nonce_b, info = "oriap/v1/session")` → 64 octets : 32 pour A→B, 32 pour B→A. Éphémères ⇒ confidentialité persistante (forward secrecy).

## 4. Canal
Trame = `compteur (u64 BE)` ‖ ChaCha20-Poly1305(nonce = 4×0 ‖ compteur). Le compteur doit être strictement croissant à la réception (anti-rejeu). Pas de réordonnancement toléré en v0.1 (transport fiable supposé).

## 5. Limites connues / à décider
- Pas de protection de l'identité contre un observateur actif (les ID transitent en clair dans hello) ; un Noise XX/IK serait un candidat.
- Pas de découverte ni de traversée NAT (étape B du rapport) ; transport non spécifié.
- Ré-ouverture de session / rotation de clés de session non définie.

## 6. Signalisation et appel (v0.1)
- Serveur WebSocket (`oriap/signaling.py`) : à la connexion, challenge `nonce` ; le client prouve la possession de la clé en signant `"oriap/v1/signal" ‖ nonce`. Le serveur tient un annuaire `ID → connexion` et relaie `{"type":"relay","to":ID,"payload":…}` sans interpréter la charge. Cible hors ligne ⇒ `{"type":"error","code":"offline"}`.
- Le serveur n'est pas de confiance : le handshake §2 passe en charge utile (`hs1`/`hs2`/`auth`), puis l'offre/réponse SDP WebRTC circule chiffrée (`enc`) sous la clé de session. L'empreinte DTLS du SDP est ainsi liée aux ID authentifiés ; le serveur ne voit ni le SDP ni le média (média = direct, DTLS-SRTP).
- `OriaNode.call(id)` (`oriap/node.py`) : un appel vocal initié uniquement à partir d'un ID Oria, sans numéro. Test : `oriap/tests/test_call.py` (audio sinusoïdal reçu par le pair en loopback).
- Traversée NAT : `OriaNode(ice_servers=[...])` ou variable `ORIA_ICE_SERVERS` (JSON, ex. `[{"urls":"stun:h:3478"},{"urls":"turn:h:3478","username":"u","credential":"c"}]`). Sans configuration : aucun serveur, LAN/loopback uniquement (pas de dépendance à un tiers par défaut). Signalisation + coturn auto-hébergés : `deploy/docker-compose.yml`.
- Identifiants TURN éphémères : `serve(turn_secret=…, turn_urls=[…])` envoie à chaque client authentifié `username = expiration`, `credential = base64(HMAC-SHA1(secret, username))` (mode `use-auth-secret` de coturn). Le secret ne quitte pas le serveur ; un client peut toujours imposer ses propres serveurs.
- Sonnerie : après le handshake, `ring` → le pair répond `accept` ou `decline` (`CallDeclined`), puis offre/réponse SDP. `bye` raccroche. Tous ces messages sont chiffrés sous la clé de session.
- Limites : STUN/TURN **non testé sur un vrai NAT** (le sandbox n'a qu'un réseau) ; le serveur voit qui appelle qui ; pas de limitation de débit ; appel de groupe en maillage seulement (voir ci-dessous), donc coûteux en bande passante au-delà de ~4-5 personnes.
- Appel de groupe : `call_group([ids])` crée une salle ; l'initiateur appelle chaque invité (`ring` avec `room`, `members`, `initiator`). Une fois accepté, chaque invité appelle les membres d'ID supérieur au sien (un seul sens par paire, pas de collision), ce qui forme un maillage complet. L'acceptation n'est demandée qu'une fois par salle ; un refus exclut seulement le refusant. Un invité qui n'a pas reçu l'invitation de l'initiateur n'est pas rejoint par les autres membres tant qu'il n'a pas répondu (l'appel entre invités attend la décision).

## 7. Fil de messages répliqué (`oriap/replication.py`)
- Message = `{id, body{author, ts, text, parents}, sig}` ; `id = SHA-256("oriap/v1/msg" ‖ corps canonique)`, `sig` = signature Ed25519 de l'auteur sur l'`id`. Tout nœud peut vérifier un message sans faire confiance à celui qui le relaie : un relais ne peut ni modifier ni falsifier un message.
- Le fil est un ensemble grow-only (CRDT) : l'union est commutative, associative, idempotente. Affichage : tri topologique (parents d'abord), départage `(ts, id)` ⇒ ordre identique sur tous les nœuds qui ont les mêmes messages. Stockage SQLite local.
- Synchronisation sur le canal chiffré OriaP : `sync_have(ids)` → `sync_reply(manquants, ids)` → `sync_msgs(manquants)`. Les nouveaux messages sont relayés de proche en proche (gossip) : A et C convergent via B sans jamais se connecter.
- Limites : liste d'ids complète à chaque synchro (non scalable) ; `ts` déclaratif (non fiable pour l'ordre, sert de départage) ; pas d'édition/suppression ; pas de chiffrement de groupe (le contenu est visible de tout nœud qui le reçoit) ; pas de contrôle d'accès au fil ; un message dont les parents manquent est accepté.

## 8. Groupes chiffrés et contrôle d'accès (`oriap/groups.py`)
- **Époques.** Un groupe est une suite d'époques ; chacune est un événement du journal signé par l'admin (le créateur) : `{kind:"epoch", epoch:n, members:[…], key_hash:SHA-256(clé)}`. L'id du groupe est l'id de l'événement d'époque 0 ; les suivants le référencent (`thread`). Seuls les événements signés par l'admin, formant une chaîne contiguë depuis 0, sont reconnus ; en cas d'équivoque (deux événements pour la même époque), l'id le plus petit gagne.
- **Clé par époque.** 32 octets aléatoires, générés par l'admin. Tout changement de membres ouvre une nouvelle époque avec une nouvelle clé : un membre retiré ne lit pas la suite, un membre ajouté ne lit pas le passé.
- **Message de groupe.** Message du journal dont `text` = ChaCha20-Poly1305(clé d'époque, nonce 96 bits, AAD = `groupe|époque|auteur`) ; `thread`, `epoch`, `nonce` sont signés avec le message. Les relais voient le chiffré, l'auteur, l'horodatage, l'époque, la taille. À la lecture, un message dont l'auteur n'était pas membre de son époque est ignoré.
- **Distribution des clés.** Entre membres, sur les canaux OriaP (message `keys`), après les éléments auxquels elles se rattachent. Une clé n'est acceptée que si SHA-256(clé) = `key_hash` signé par l'admin et si l'on est membre de l'époque ; un pair ne peut donc pas imposer une fausse clé. Les clés reçues sont relayées aux autres membres joignables, ce qui permet à un membre de rattraper via n'importe quel autre membre (pas besoin de l'admin).
- **Diffusion contrôlée.** Un nœud n'annonce ni n'envoie un élément de groupe qu'à un membre : messages → membres de leur époque ; événements d'époque → membres de cette époque ou de l'époque courante (un nouveau membre reçoit toute la chaîne). Les messages publics (sans `thread`) restent diffusés à tous.
- **Limites connues.**
  - Un membre retiré peut encore fabriquer un message avec l'ancienne clé, daté de l'ancienne époque : il est indiscernable d'un message légitime retardé (pas d'autorité d'ordre). Atténuation possible : l'admin signe, à chaque rotation, l'ensemble des messages de l'époque close.
  - Un membre peut divulguer les clés/le clair qu'il connaît (inévitable) ; pas de confidentialité persistante ni de ratchet au sein d'une époque (une clé compromise expose toute l'époque).
  - Admin unique et non transférable ; perte de la clé de l'admin = plus de gestion des membres.
  - Les clés sont stockées en clair dans la base SQLite locale (protection du disque = celle de l'appareil).
  - Métadonnées visibles des membres et des relais : qui écrit, quand, quelle époque, quelle taille.

## 9. Suite
1. Tests sur un vrai NAT (`docs/PROXMOX_TEST.md`), SFU pour les grands groupes, commande CLI d'appel de groupe.
2. Scellement d'époque par l'admin (anti-injection post-retrait), ratchet de clés, synchro par plages (Merkle/IBLT).
3. Rotation/révocation de clé d'identité, multi-appareils, noms lisibles.
