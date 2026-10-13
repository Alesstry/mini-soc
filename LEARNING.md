# 📓 Diario de aprendizaje

Mi mapa de qué hace cada pieza y **por qué** está así. Lo voy completando con mis propias palabras.

## Cómo estudiar este repo (orden sugerido)
1. `docker-compose.yml` → ¿qué red toca qué contenedor? ¿por qué `internal: true`?
2. `lab/victim/` → ¿cómo llega un login de SSH a `auth.log`? (sshd → /dev/log → rsyslog → archivo)
3. `lab/shipper/shipper.py` → ¿qué pasa si la plataforma está caída?
4. `platform/app/normalizer.py` → una línea cruda se convierte en un `Event`.
5. `platform/app/detection.py` → el corazón: umbral, ventana, cooldown.
6. `platform/tests/` → cómo se prueba una detección sin correr un ataque real.

## Conceptos clave (y por qué)

| Concepto | Dónde | Por qué importa |
|---|---|---|
| Segmentación de redes | `docker-compose.yml` | Si comprometen la víctima, el SOC sigue a salvo. Es el principio de defensa en profundidad. |
| Mínimo privilegio | Dockerfiles (`USER soc`), volumen `:ro` | Cada pieza tiene solo los permisos que necesita. |
| Entrada no confiable | `models.py`, `normalizer.py` | Los logs los controla parcialmente el atacante (log injection). |
| Normalización (ECS) | `models.py` | Un idioma común para todas las fuentes → reglas reutilizables. |
| Umbral + ventana + cooldown | `detection.py` | Equilibrio entre detectar y no ahogar al analista en ruido (*alert fatigue*). |
| MITRE ATT&CK | `detection.py` | Lenguaje común: "T1110.001" lo entiende cualquier equipo de seguridad. |
| Secretos fuera del código | `config.py`, `.env` | Nunca subir claves a git. |
| Comparación en tiempo constante | `main.py` | Evita *timing attacks* al validar la API key. |
| Concurrencia | `storage.py` (`lock`) | Contar → decidir → alertar debe ser atómico o aparecen alertas duplicadas. |
| Tests deterministas | `test_detection.py` | Usan el tiempo del evento, no el reloj. Así se prueba sin esperar. |

## Preguntas para comprobar que entendí
- [ ] ¿Qué pasaría con un ataque que prueba 1 contraseña cada 61 segundos? ¿Cómo lo detectaría?
- [ ] ¿Por qué SOC-002 es más grave que SOC-001?
- [ ] ¿Por qué el shipper no está en la misma red que el atacante?
- [ ] ¿Qué pasa si el atacante pone `x from 9.9.9.9 port 1` como nombre de usuario? (mira el test de injection)
- [ ] ¿Por qué contamos con la hora del evento y no con `datetime.now()`?

## Ejercicios (cada uno = un commit)
1. **Regla SOC-003: enumeración de usuarios.** Alerta si una IP prueba ≥3 usuarios inexistentes en 60 s (T1087 Account Discovery). El evento `ssh_invalid_user` ya se genera.
2. **Persistencia del offset en el shipper**, para no perder líneas si se reinicia.
3. **Subir/bajar el umbral** (`BF_THRESHOLD`) y ver cómo cambian detecciones y falsos positivos. Anota lo que observes.
4. **Ataque lento**: modifica el script con `-W`/pausas largas y comprueba que evade SOC-001. Luego diseña una regla que lo atrape.
5. Endpoint `GET /alerts?severity=critical`.

## Registro
| Fecha | Qué hice | Qué aprendí |
|---|---|---|
| | Levanté el lab y lancé el primer ataque | |
