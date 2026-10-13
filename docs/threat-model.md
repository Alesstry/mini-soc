# Threat model

Un SOC es un objetivo de alto valor: si el atacante lo ciega o lo manipula, opera sin ser visto. Este documento describe qué protegemos y de quién.

## Activos
- **Integridad de los logs/eventos**: si se falsifican, las detecciones pierden valor.
- **Disponibilidad de la ingesta**: si se satura, se pierde visibilidad.
- **Confidencialidad de las alertas**: revelan qué vemos y qué no.
- **API key de ingesta**: quien la tenga puede inyectar eventos falsos.

## Adversarios considerados
1. **Atacante externo contra el servidor monitoreado** (el del lab: fuerza bruta SSH).
2. **Atacante que ya comprometió el servidor monitoreado** e intenta evadir o envenenar la detección.

## Límites de confianza
```
[Internet/atacante] ──► [victim]  ── (logs) ──► [shipper] ──► [platform]
        no confiable      parcialmente confiable     confiable    núcleo confiable
```
La víctima puede estar comprometida, por lo tanto **todo dato que sale de ella es entrada no confiable**.

## Amenazas y mitigaciones

| # | Amenaza (STRIDE) | Mitigación actual | Pendiente |
|---|---|---|---|
| 1 | **Spoofing**: alguien inyecta eventos falsos en `/ingest` | API key (comparación en tiempo constante) | TLS + mTLS, claves por agente, rotación |
| 2 | **Tampering / log injection**: el atacante mete texto en campos (usuario) para falsificar IP/acciones | Regex ancladas, `\S+` estricto, test dedicado | Validar contra esquema por fuente |
| 3 | **DoS** de la ingesta con payloads gigantes o flood | Límites de tamaño en el modelo | Rate limiting, cola de ingesta |
| 4 | **Repudiation**: no poder probar qué pasó | Evento crudo guardado junto al normalizado | Almacén append-only / firmado |
| 5 | **Info disclosure**: lectura de alertas | API key en lectura; puerto atado a 127.0.0.1 | RBAC, TLS |
| 6 | **Evasión**: ataque "low and slow" (1 intento cada 61 s) | Documentado como limitación | Reglas con ventanas más largas y baselines |
| 7 | **Pérdida de logs** si el shipper cae | Reintentos con backoff | Cola persistente / offset en disco |
| 8 | **Movimiento lateral** víctima → plataforma | Redes separadas; atacante sin ruta a `mgmt_net`; volumen `read-only` | Firewall entre segmentos |

## Fuera de alcance (por ahora)
Ataques al kernel o al runtime de Docker, DDoS volumétrico, amenazas internas con acceso al host del lab.
