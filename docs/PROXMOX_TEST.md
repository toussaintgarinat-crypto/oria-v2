# Essai en conditions réelles (VM Proxmox)

Objectif : valider ce que le sandbox ne peut pas tester — appel et messages entre **deux vrais réseaux** (NAT), via STUN/TURN.
Rien de ce qui suit n'a été exécuté par l'auteur : c'est le protocole d'essai. Notez ce qui diffère.

## 1. VM serveur (signalisation + coturn)
- Debian/Ubuntu récent, 1 vCPU / 512 Mo suffisent, Docker + plugin compose installés.
- **Ports à ouvrir** (pare-feu Proxmox, VM et routeur si la VM est derrière une box) :

| Port | Proto | Usage |
|---|---|---|
| 8765 | TCP | signalisation WebSocket |
| 3478 | UDP + TCP | STUN/TURN |
| 49152–49252 | UDP | relais TURN |

- Cloner le dépôt, puis :
```
cp deploy/.env.example deploy/.env      # PUBLIC_IP, ORIA_TURN_SECRET (openssl rand -hex 32)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.yml logs -f coturn
```
- **VM derrière un NAT** : `PUBLIC_IP` = IP publique de la box, et décommenter `TURN_EXTERNAL_IP=PUBLIQUE/PRIVEE_DE_LA_VM`, sinon TURN annonce une adresse injoignable.
- ⚠️ Le compose n'interdit pas les plages privées côté coturn (nécessaire pour tester entre VM du LAN). Pour une exposition réelle, ajouter `--denied-peer-ip=10.0.0.0-10.255.255.255` (idem 172.16/12, 192.168/16) et ne pas laisser 8765 en clair : placer la signalisation derrière un reverse proxy TLS (`wss://`).

## 2. Postes clients (2 ou 3, idéalement sur des réseaux différents : box + partage 4G)
```
git clone https://github.com/toussaintgarinat-crypto/oria-v2 && cd oria-v2
pip install -r requirements.txt
python -m oriap id --key moi.key        # affiche votre ID Oria (crée la clé en 0600)
```
Les clients reçoivent automatiquement les identifiants TURN éphémères du serveur ; rien à configurer côté poste.

## 3. Scénarios, du plus simple au plus dur
1. **Même LAN** — B : `python -m oriap listen --url ws://IP_VM:8765 --key b.key --out recu_b.wav`. A : `python -m oriap call --url ws://IP_VM:8765 --key a.key --to <ID de B> --seconds 5`. Attendu : « appel établi » chez A, « appel de … accepté » chez B, `recu_b.wav` non vide (~440 Hz).
2. **Réseaux différents** (A en 4G, B sur la box) — même commande. C'est le vrai test NAT. Si ça échoue : `docker compose logs coturn` (le client atteint-il 3478 ? y a-t-il des `allocation` ?), puis vérifier les ports/forwards.
3. **Refus** — B avec `--decline` : A affiche « appel refusé ».
4. **Appel de groupe** — 3 clients en `listen`, puis depuis A (script Python : `await node.call_group([id_b, id_c])`, voir `oriap/tests/test_call.py::GroupCallTest`). Pas encore de commande CLI dédiée.
5. **Messages à 3 nœuds** — `python -m oriap chat --url ws://IP_VM:8765 --key x.key --db x.db` sur chaque poste ; A fait `/sync <ID de B>`, C fait `/sync <ID de B>` ; écrire depuis A, C et B simultanément ; `/fil` doit afficher le même ordre partout. Couper C, écrire sur A, relancer C et `/sync <ID de B>` : C doit rattraper.

## 4. À savoir pour interpréter les résultats
- Le client n'a pas de mode « relais seulement » : un appel qui réussit peut passer en direct (STUN) plutôt que par TURN. Pour prouver que TURN fonctionne, regardez les `allocation` dans les logs coturn, ou bloquez l'UDP direct entre les deux postes.
- Le serveur de signalisation voit qui appelle qui (métadonnées), pas le contenu (chiffré de bout en bout) ni l'audio.
- Les messages du fil ne sont pas chiffrés pour le groupe : tout nœud qui les reçoit les lit.
