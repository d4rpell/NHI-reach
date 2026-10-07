# nhi-reach

**Estado (2026-10-07): spec aprobada (rev. 3, T0-01 cerrado); dirección, arquitectura y enfoque del motor aceptados. Sin código todavía.** Este README es el documento de trabajo en español; la versión pública se escribe en inglés en T3-03.

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
| [KubeHound](https://github.com/DataDog/KubeHound) (Datadog) | Grafo de rutas de ataque en K8s | Su README enumera Docker y Docker Compose V2 como requisitos y documenta consultas Gremlin (TinkerPop); también ofrece un modo servicio (KHaaS). nhi-reach es un solo binario offline, centrado en NHI, con cortes verificados. En su [portada](https://kubehound.io/) y su [índice de ataques](https://kubehound.io/reference/attacks/), consultados el 2026-10-07, no se encontraron menciones a las SCC de OpenShift |
| KubiScan / rbac-tool | Permisos de riesgo / visualización RBAC | No calculan cadenas de escalada |

Estado de estas herramientas consultado el 2026-10-07 vía la API de GitHub: [KubeHound](https://github.com/DataDog/KubeHound), último push 2026-09-30; [rbac-police](https://github.com/PaloAltoNetworks/rbac-police), archivado; [KubiScan](https://github.com/cyberark/KubiScan) y [rbac-tool](https://github.com/alcideio/rbac-tool), sin pushes desde 2025; [nhi-watch](https://github.com/Zyrakk/nhi-watch), último push 2026-03-16.

## Principios

- **Solo lectura**, siempre: nunca crea, modifica ni ejecuta nada en el clúster.
- **Offline primero**: analiza snapshots exportados; el modo live es opcional (`get`/`list`).
- **Determinista**: mismo snapshot → mismo JSON, byte a byte.
- **Evidence-first** (misma línea que Ariadne): cada arista cita los objetos que la habilitan, con hash.
- **Nunca guarda valores de Secrets**, solo referencias (`ns/name`, tipo y nombres de clave).

## Documentación

Las decisiones de diseño, el backlog y la spec de diseño se mantienen en documentación privada del proyecto y no se enlazan desde aquí. La versión pública de este README, en inglés, llega en T3-03.

## Stack previsto

Go con Cobra, client-go (solo en modo live), salida en tabla/JSON/HTML (SARIF fuera del MVP), plantilla HTML embebida con la librería de grafos inline y GoReleaser. Las versiones exactas se fijan en la tarea de scaffolding (T0-03).
