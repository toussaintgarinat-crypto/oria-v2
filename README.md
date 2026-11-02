# Oria v2

Projet séparé de Oria (original intact). Voir `docs/ORIAP_SPEC.md`.

Installation : `pip install -r requirements.txt`
Tests : `python3 -m unittest discover -s oriap/tests -t .`

## Appel entre deux réseaux
Fournir un STUN/TURN : `export ORIA_ICE_SERVERS='[{"urls":"stun:IP:3478"},{"urls":"turn:IP:3478","username":"u","credential":"c"}]'`.
Un coturn auto-hébergé + la signalisation : voir `docs/PROXMOX_TEST.md` (`deploy/docker-compose.yml`).

## Démonstration (deux terminaux + un serveur)
```
python -m oriap serve --port 8765                                   # signalisation (+ --turn-secret S --turn-url turn:IP:3478)
python -m oriap listen --url ws://HOTE:8765 --key b.key --out recu.wav   # affiche son ID ; --decline pour refuser
python -m oriap call   --url ws://HOTE:8765 --key a.key --to oria:ID_DE_B --seconds 5
python -m oriap chat   --url ws://HOTE:8765 --key a.key --db a.db [--peer oria:ID]   # fil public + groupes chiffrés ; /sync ID, /fil, /groupe, /g, /lire, /membres
```
Les clés (`*.key`, créées en 0600) sont des graines privées : ne pas les committer ni les partager.
