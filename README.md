# dsh-plugin-secrets-scanner — Secrets Scanner

Escanea un proyecto local en busca de secretos y credenciales (claves, tokens, passwords, claves privadas) con patrones, enmascarado y excluding de dependencias.

## Herramientas

| Tool | Qué hace |
|---|---|
| `status` | Estado |
| `patterns` | Patrones |
| `scan` | Escanear secretos |

## Instalación

Desde **DSH → Settings → Plugins** instala `github:thegabopacheco-sudo/dsh-plugin-secrets-scanner` y permite el script de instalación.

```
dsh plugin --profile <perfil> add github:thegabopacheco-sudo/dsh-plugin-secrets-scanner
```

## Seguridad

- Lectura por defecto; escritura solo con `confirm:true` y pedido explícito.
- `DSH_SECRETS_SCANNER_MODE=read-only` desactiva acciones.
- Listas blancas y auditoría en `<DSH_HOME>\cache\secrets-scanner\audit.jsonl`.

## Licencia

MIT © thegabopacheco-sudo
