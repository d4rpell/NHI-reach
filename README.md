# nhi-reach

**Estado (2026-10-07): versión light funcionando de punta a punta (T1-00); spec de diseño aprobada (rev. 3); tipos compartidos congelados (T0-04).** `nhi-reach analyze --from DIR -o table` ya lee un snapshot offline, resuelve los permisos directos de cada ServiceAccount y traza la ruta más corta por origen hasta `cluster-admin`, encadenando dos tipos de arista: el binding directo y el salto **NR-001** (poder crear workloads en un namespace da el nivel de acceso de cualquier ServiceAccount de ese namespace, según la documentación oficial de Kubernetes). Todavía **no** hay cortes, ni salida JSON/HTML, ni modo live; los permisos efectivos cubren solo sujetos directos, sin grupos implícitos, agregación ni `resourceNames`; el objetivo evaluado es `cluster-admin`. El catálogo completo de saltos llega con T1-03/T1-04 y la evidencia impresa con T2-01/T2-03. Este README es el documento de trabajo en español; la versión pública se escribe en inglés en T3-03.

> ¿Hasta dónde puede llegar esta identidad no humana?

`nhi-reach` es una herramienta defensiva y de solo lectura para auditar identidades no humanas (NHI) en Kubernetes/OpenShift. El diseño analiza ServiceAccounts, sus tokens y sus vínculos RBAC/SCC, y calcula qué **rutas de escalada de privilegios** existen desde cada identidad hacia tres objetivos críticos (la versión light evalúa hoy solo el primero):

1. Privilegios equivalentes a `cluster-admin`.
2. Control de un nodo (workloads privilegiados, `hostPath`, SCC permisivas).
3. Lectura de Secrets de namespaces sensibles.

El diseño incluye, para cada ruta, la **evidencia de cada salto** (los objetos RBAC/SCC citados, con hash SHA-256) y **propuestas de corte verificadas en el modelo**: qué concesión concreta retirar (un sujeto de un binding, una regla) y si con eso el objetivo deja de ser alcanzable. La versión light ya calcula esa evidencia por arista y los tests la comprueban; imprimirla en el informe llega con T2-01 (JSON) y T2-03 (HTML).

Por defecto, las identidades de sistema (`kube-system`, `openshift-*`…) no son origen del análisis pero sí pueden ser saltos intermedios; destacar en el informe las rutas que, desde una SA de aplicación, pasan por una de sistema llega con T1-05.

## Posicionamiento

| Herramienta | Qué hace | Diferencia con nhi-reach |
|---|---|---|
| [nhi-watch](https://github.com/Zyrakk/nhi-watch) | Inventario NHI, scoring por identidad, CIS, drift, inactividad, RBAC mínimo por uso | Evalúa cada identidad aislada y no encadena permisos. **Complementaria**: nhi-reach podría consumir su JSON más adelante |
| [KubeHound](https://github.com/DataDog/KubeHound) (Datadog) | Grafo de rutas de ataque en K8s | Su README enumera Docker y Docker Compose V2 como requisitos y documenta consultas Gremlin (TinkerPop); también ofrece un modo servicio (KHaaS). nhi-reach es un solo binario offline, centrado en NHI, con cortes verificados en el modelo previstos. En su [portada](https://kubehound.io/) y su [índice de ataques](https://kubehound.io/reference/attacks/), consultados el 2026-10-07, no se encontraron menciones a las SCC de OpenShift |
| KubiScan / rbac-tool | Permisos de riesgo / visualización RBAC | No calculan cadenas de escalada |

Estado de estas herramientas consultado el 2026-10-07 vía la API de GitHub: [KubeHound](https://github.com/DataDog/KubeHound), último push 2026-09-30; [rbac-police](https://github.com/PaloAltoNetworks/rbac-police), archivado; [KubiScan](https://github.com/cyberark/KubiScan) y [rbac-tool](https://github.com/alcideio/rbac-tool), sin pushes desde 2025; [nhi-watch](https://github.com/Zyrakk/nhi-watch), último push 2026-03-16.

## Principios

- **Solo lectura**, siempre: nunca crea, modifica ni ejecuta nada en el clúster.
- **Offline primero**: analiza snapshots exportados; el modo live previsto usará únicamente `get`/`list`.
- **Determinista**: mismo snapshot → misma salida, byte a byte (hoy la tabla; el JSON llega con T2-01).
- **Evidence-first** (misma línea que Ariadne): cada arista lleva referencias a los objetos que la habilitan, con su hash.
- **Nunca guarda valores de Secrets**: solo referencias (`ns/name` y `type`; los nombres de clave llegan con T1-01).

## Uso (estado actual)

```bash
go run ./cmd/nhi-reach analyze --from testdata/light/hit
```

Imprime una fila por ruta alcanzada (origen, objetivo, número de saltos, confianza y la secuencia de saltos) y, debajo, los `gaps` del análisis. Los dos fixtures del repo son sintéticos: `testdata/light/hit` tiene una ruta esperada y `testdata/light/miss` no tiene ninguna. El formato de entrada es el JSON de `kubectl get <recurso> -o json`, una lista o un objeto suelto por fichero.

Hoy funcionan `--from`, `-o table`, `--max-depth`, `--from-identity`, `--system-ns`, `--include-system` y `--target cluster-admin`. Cualquier otro flag o valor que la herramienta todavía no implementa (por ejemplo `-o json`, `--live`, `--target node`) termina con código de salida 3 en lugar de ignorarse en silencio; con `go run`, `go` lo presenta como `exit status 3` y devuelve 1, mientras que el binario devuelve 3.

## Documentación

Las decisiones de diseño, el backlog y la spec de diseño se mantienen en documentación privada del proyecto y no se enlazan desde aquí. La versión pública de este README, en inglés, llega en T3-03.

## Stack previsto

Go con Cobra, client-go (solo en modo live), salida en tabla/JSON/HTML (SARIF fuera del MVP), plantilla HTML embebida con la librería de grafos inline y GoReleaser. El andamiaje (T0-03) fija el módulo `github.com/d4rpell/nhi-reach` en `go 1.23` con Cobra, y la versión light (T1-00) añade los paquetes `internal/snapshot`, `internal/rbac`, `internal/hops`, `internal/graph` y `internal/report`; las demás versiones se fijan al implementar cada pieza.
