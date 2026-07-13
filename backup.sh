#!/bin/bash
set -euo pipefail
source /root/.config/restic/env

SNAP="/tmp/node0-mesh-snapshot.db"

# 1) Konsistenten DB-Schnappschuss erzeugen
/opt/node0/venv/bin/python /opt/node0/db_snapshot.py "$SNAP"

# 2) Verschluesseltes Backup: DB-Schnappschuss + Code + Secrets + Agenten-Schluessel + Configs
restic backup \
  "$SNAP" \
  /opt/node0 \
  /etc/nginx/sites-available \
  /etc/systemd/system/node0* \
  /etc/ssh/sshd_config.d \
  --exclude /opt/node0/venv \
  --exclude /opt/node0/mesh.db \
  --exclude "/opt/node0/*.bak" \
  --exclude "/opt/node0/*.db" \
  --tag node0 --host node0

# 3) Schnappschuss-Datei aufraeumen
rm -f "$SNAP"

# 4) Aufbewahrung ausduennen (7 taeglich, 4 woechentlich, 6 monatlich)
restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
