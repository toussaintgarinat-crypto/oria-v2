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

## 6. Suite
1. Transport + signalisation WebSocket, puis WebRTC (appel par ID).
2. Réplication de messages signés (journal d'événements ou CRDT) entre 3 nœuds.
