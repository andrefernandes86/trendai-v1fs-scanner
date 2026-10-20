#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo 'Run this installer as root on the host (not inside an unprivileged sandbox).' >&2; exit 1; fi
app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
app_user=${APP_USER:-skynet}
app_group=$(id -gn "$app_user")
app_data=${V1FS_DATA_DIR:-"$(dirname "$app_root")/work/trendai-host-data"}
app_binary=${V1FS_BINARY:-"$(dirname "$app_root")/work/trendai-v1fs-local"}
if [[ ! -x "$app_binary" ]]; then echo "Build executable first: $app_binary" >&2; exit 1; fi
install -d -m 700 -o "$app_user" -g "$app_group" "$app_data"
install -d -m 755 /etc/trendai-v1fs-scanner
# Use a structured renderer so whitespace and shell metacharacters in paths do not execute.
python3 - "$app_root" "$app_user" "$app_group" "$app_data" "$app_binary" <<'PY'
import pathlib,sys
root,user,group,data,binary=sys.argv[1:]
if any('\n' in x or '\r' in x or '"' in x or '%' in x for x in [root,user,group,data,binary]): raise SystemExit('Unsupported newline, quote or % in service paths')
values={'ROOT':root,'USER':user,'GROUP':group,'DATA':data,'BINARY':binary,'ENV':'/etc/trendai-v1fs-scanner/host.env'}
text=(pathlib.Path(root)/'deploy/trendai-v1fs-scanner.service.in').read_text()
for key,value in values.items(): text=text.replace('@'+key+'@','"'+value+'"' if key in ['ROOT','DATA','BINARY','ENV'] else value)
pathlib.Path('/etc/systemd/system/trendai-v1fs-scanner.service').write_text(text)
pathlib.Path('/etc/trendai-v1fs-scanner/host.env').write_text('V1FS_DATA_DIR="'+data+'"\nV1FS_WEB_DIR="'+root+'/dist"\nPORT=8095\n')
PY
chmod 600 /etc/trendai-v1fs-scanner/host.env
systemctl daemon-reload
systemctl enable trendai-v1fs-scanner.service
echo 'Service installed and enabled. Stop any foreground instance, then run: systemctl start trendai-v1fs-scanner.service'
