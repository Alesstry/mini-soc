# ADR 0003: Reglas de detección en Python primero, Sigma después

**Estado:** aceptada (revisar en Fase 4)

## Contexto
Sigma es el estándar de reglas de detección, pero para entender qué hace un motor de detección conviene escribir uno primero.

## Decisión
Implementar las primeras reglas como clases Python (umbral, ventana, cooldown). En la Fase 4 se añadirá un traductor Sigma → motor interno.

## Consecuencias
- (+) Se entienden de verdad ventanas de tiempo, correlación y deduplicación antes de usar una abstracción.
- (+) Tests unitarios simples y deterministas (usa el tiempo del evento, no el del reloj).
- (−) Las reglas actuales no son portables a otros SIEM hasta la Fase 4.
