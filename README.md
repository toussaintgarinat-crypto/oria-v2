# Oria v2

Projet séparé de Oria (original intact). Voir `docs/ORIAP_SPEC.md`.

Installation : `pip install -r requirements.txt`
Tests : `python3 -m unittest discover -s oriap/tests -t .`

## Appel entre deux réseaux
Fournir un STUN/TURN : `export ORIA_ICE_SERVERS='[{"urls":"stun:IP:3478"},{"urls":"turn:IP:3478","username":"u","credential":"c"}]'`.
Un coturn auto-hébergé : `deploy/docker-compose.turn.yml` + `deploy/turnserver.conf` (remplacer les `CHANGE_ME`).
