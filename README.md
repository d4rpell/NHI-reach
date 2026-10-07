# nhi-reach

**Estado: diseño en revisión (2026-10-06): dirección y arquitectura aprobadas; spec §2–§5 pendiente de revisión del propietario. Sin código todavía.** Este README es el documento de trabajo en español; la versión pública se escribe en inglés en T3-03 (D-012).

> ¿Hasta dónde puede llegar esta identidad no humana?

`nhi-reach` es una herramienta defensiva y de solo lectura para auditar identidades no humanas (NHI) en Kubernetes/OpenShift. Analiza ServiceAccounts, sus tokens y sus vínculos RBAC/SCC, y calcula qué **rutas de escalada de privilegios** existen desde cada identidad hacia tres objetivos críticos:

1. Privilegios equivalentes a `cluster-admin`.
2. Control de un nodo (workloads privilegiados, `hostPath`, SCC permisivas).
3. Lectura de Secrets de namespaces sensibles.

Para cada ruta entrega la **evidencia de cada salto** (los objetos RBAC/SCC citados, con hash SHA-256) y **propuestas de corte verificadas en el modelo**: qué concesión concreta retirar (un sujeto de un binding, una regla) y si con eso el objetivo deja de ser alcanzable.

Por defecto, las identidades de sistema (`kube-system`, `openshift-*`…) no son origen del análisis pero sí pueden ser saltos intermedios. Se destacan las rutas que, desde una SA de aplicación, pasan por una de sistema.

## Posicionamiento

| Herramienta | Qué hace | Diferencia con nhi-reach |
|---|---|---|
| [nhi-watch](https://github.com/Zyrakk/nhi-watch) | Inventario NHI, scoring por identidad, CIS, drift, inactividad, RBAC mínimo por uso | Evalúa cada identidad aislada y no encadena permisos. **Complementaria**: nhi-reach podría consumir su JSON más adelante |
| KubeHound (Datadog) | Grafo de rutas de ataque en K8s | Requiere stack Docker Compose + base de datos de grafos. nhi-reach es un solo binario offline, centrado en NHI, con cortes verificados. Soporte de SCC en KubeHound sin comprobar (T0-02) |
| KubiScan / rbac-tool | Permisos de riesgo / visualización RBAC | No calculan cadenas de escalada |

Estado de estas herramientas consultado el 2026-10-06 (API de GitHub; rbac-police está archivado). Ver [`docs/decisions.md`](docs/decisions.md).

## Principios

- **Solo lectura**, siempre: nunca crea, modifica ni ejecuta nada en el clúster.
- **Offline primero**: analiza snapshots exportados; el modo live es opcional (`get`/`list`).
- **Determinista**: mismo snapshot → mismo JSON, byte a byte.
- **Evidence-first** (misma línea que Ariadne): cada arista cita los objetos que la habilitan, con hash.
- **Nunca guarda valores de Secrets**, solo referencias (`ns/name`, tipo y nombres de clave).

## Documentación

- [Spec de diseño](docs/specs/2026-10-06-nhi-reach-design.md) (rev. 2): arquitectura, modelo de datos, saltos, salida y testing.
- [Decisiones](docs/decisions.md): qué se decidió, alternativas y por qué.
- [`TODO.md`](TODO.md): backlog y orden de ejecución.
- [`CLAUDE.md`](CLAUDE.md): reglas del proyecto para sesiones de IA.

## Stack previsto

Go con Cobra, client-go (solo en modo live), salida en tabla/JSON/HTML (SARIF fuera del MVP, D-010), plantilla HTML embebida con la librería de grafos inline y GoReleaser. Las versiones exactas se fijan en la tarea de scaffolding (T0-03).
