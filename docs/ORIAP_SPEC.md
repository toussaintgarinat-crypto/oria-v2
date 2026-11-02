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
- Traversée NAT : `OriaNode(ice_servers=[...])` ou variable `ORIA_ICE_SERVERS` (JSON, ex. `[{"urls":"stun:h:3478"},{"urls":"turn:h:3478","username":"u","credential":"c"}]`). Sans configuration : aucun serveur, LAN/loopback uniquement (pas de dépendance à un tiers par défaut). Un coturn auto-hébergé est fourni dans `deploy/`.
- Identifiants TURN éphémères : `serve(turn_secret=…, turn_urls=[…])` envoie à chaque client authentifié `username = expiration`, `credential = base64(HMAC-SHA1(secret, username))` (mode `use-auth-secret` de coturn). Le secret ne quitte pas le serveur ; un client peut toujours imposer ses propres serveurs.
- Sonnerie : après le handshake, `ring` → le pair répond `accept` ou `decline` (`CallDeclined`), puis offre/réponse SDP. `bye` raccroche. Tous ces messages sont chiffrés sous la clé de session.
- Limites : STUN/TURN **non testé sur un vrai NAT** (le sandbox n'a qu'un réseau) ; le serveur voit qui appelle qui ; pas de limitation de débit ; appel à deux uniquement (pas d'appel de groupe).

## 7. Fil de messages répliqué (`oriap/replication.py`)
- Message = `{id, body{author, ts, text, parents}, sig}` ; `id = SHA-256("oriap/v1/msg" ‖ corps canonique)`, `sig` = signature Ed25519 de l'auteur sur l'`id`. Tout nœud peut vérifier un message sans faire confiance à celui qui le relaie : un relais ne peut ni modifier ni falsifier un message.
- Le fil est un ensemble grow-only (CRDT) : l'union est commutative, associative, idempotente. Affichage : tri topologique (parents d'abord), départage `(ts, id)` ⇒ ordre identique sur tous les nœuds qui ont les mêmes messages. Stockage SQLite local.
- Synchronisation sur le canal chiffré OriaP : `sync_have(ids)` → `sync_reply(manquants, ids)` → `sync_msgs(manquants)`. Les nouveaux messages sont relayés de proche en proche (gossip) : A et C convergent via B sans jamais se connecter.
- Limites : liste d'ids complète à chaque synchro (non scalable) ; `ts` déclaratif (non fiable pour l'ordre, sert de départage) ; pas d'édition/suppression ; pas de chiffrement de groupe (le contenu est visible de tout nœud qui le reçoit) ; pas de contrôle d'accès au fil ; un message dont les parents manquent est accepté.

## 8. Suite
1. Appel de groupe (maillage ou SFU), tests sur un vrai NAT.
2. Chiffrement de groupe pour les messages, contrôle d'accès, synchro par plages (Merkle/IBLT).
3. Rotation/révocation de clé, multi-appareils, noms lisibles.
