# ADR 0002: Normalizar eventos a un esquema tipo ECS

**Estado:** aceptada

## Contexto
Cada fuente de logs usa un formato distinto. Si las reglas dependieran del formato crudo, cada nueva fuente obligaría a reescribirlas.

## Decisión
Normalizar a un modelo interno (`Event`) con proyección a **ECS** (Elastic Common Schema): `event.action`, `event.outcome`, `source.ip`, `user.name`, etc. Se conserva el log crudo en `message`.

## Consecuencias
- (+) Las reglas se escriben una vez sobre campos comunes; compatible con Sigma y OpenSearch.
- (+) Añadir una fuente = añadir un normalizador.
- (−) Se pierde algo de detalle específico de cada fuente (mitigado guardando el crudo).
