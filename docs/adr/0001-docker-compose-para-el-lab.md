# ADR 0001: Docker Compose para el laboratorio

**Estado:** aceptada

## Contexto
Necesitamos un lab con víctima, atacante y plataforma, aislado y reproducible con un solo comando.

## Opciones
1. **VMs (Vagrant/VirtualBox)**: más realistas (kernel propio, auditd completo) pero pesadas y lentas en CI.
2. **Docker Compose**: ligero, reproducible, corre en GitHub Actions, redes aisladas nativas.
3. **Cloud (Terraform)**: realista pero con costo y riesgo de exposición.

## Decisión
Docker Compose, con dos redes (`attack_net` interna y `mgmt_net`).

## Consecuencias
- (+) `make up` y listo; el CI puede levantar el lab.
- (+) Segmentación de red demostrable.
- (−) Los contenedores comparten kernel: no sirven para detecciones a nivel kernel/auditd completas. Para la Fase 2 podría añadirse una VM.
