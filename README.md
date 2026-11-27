# Priorización de vulnerabilidades

Sitio estático trilingüe (español, portugués, inglés) que cruza NVD, CISA KEV, EPSS y SSVC con señales de exploit público y asigna a cada vulnerabilidad una prioridad de P1 a P4.

Versión en línea: https://noelinares-svg.github.io/vulnerabilitiestrend/

## Estructura

| Ruta | Qué es |
|---|---|
| `site/index.html` | El sitio completo: HTML, estilos y lógica en un solo archivo |
| `site/logo-light.svg`, `site/logo-dark.svg` | Logo de Vicarius para tema claro y oscuro |
| `site/data.json` | Datos. Se genera en cada actualización; no se guarda en el repositorio |
| `scripts/collect.py` | Recolector: descarga las fuentes y genera `data.json` (Python 3, sin dependencias externas) |
| `.github/workflows/actualizar.yml` | Tarea programada: actualiza cada 3 horas y publica en GitHub Pages |

## Cómo funciona

1. `collect.py` consulta las fuentes públicas y escribe `site/data.json` (unos 2 MB).
2. `index.html` lee ese archivo y dibuja indicadores, gráficos y tabla en el navegador.
3. No hay servidor ni base de datos: cualquier hosting de archivos estáticos sirve.

## Probarlo en un equipo

```
python scripts/collect.py site/data.json
python -m http.server 8000 --directory site
```

Luego abrir http://localhost:8000. La recolección tarda de 3 a 4 minutos sin clave de la NVD.

## Llevarlo al sitio oficial

- **Archivos a publicar:** el contenido de `site/` más un `data.json` actualizado.
- **Actualización de datos:** programar `collect.py` cada 3 horas (cron, GitHub Actions u otro) y publicar el `data.json` resultante junto al sitio.
- **Clave de la NVD (opcional):** variable de entorno `NVD_API_KEY`. Es gratuita y acelera la recolección. No va dentro del código.
- **Integración:** como página propia o dentro de un `iframe`. El archivo no depende de ningún framework.
- **Dependencias externas en el navegador:** Chart.js 4.4.1 (cdnjs) y las fuentes Albert Sans y JetBrains Mono (Google Fonts). Se pueden alojar localmente.

## Personalización rápida

- **Textos e idiomas:** objeto `T` al inicio del script en `index.html`; cada clave tiene `[español, portugués, inglés]`.
- **Colores y tipografía:** variables CSS en el bloque `:root` (tema claro) y sus equivalentes de tema oscuro.
- **Tipografía de marca:** la guía de Vicarius usa Basier Square, que es comercial. Aquí se usa Albert Sans como alternativa libre; para cambiarla basta con cargar Basier Square y ajustar `--font`.
- **Enlace de demo:** `https://www.vicarius.io/request-a-demo`, usado en el botón final y en cada fila de la tabla.
- **Reglas de prioridad:** función `prio()` en `index.html`.
- **Países de la sección de ransomware:** lista `AMERICAS` en `collect.py` y objeto `REG` en `index.html`.

## Fuentes de datos

| Fuente | Uso |
|---|---|
| NVD (NIST), API 2.0 | CVE, CVSS, CPE, fechas |
| CISA KEV | Vulnerabilidades con explotación confirmada |
| EPSS (FIRST) | Probabilidad de explotación |
| SSVC (CISA Vulnrichment) | Explotación, automatización, impacto |
| Nuclei, Metasploit, Exploit-DB | Existencia de exploit público |
| ransomware.live | Conteos de víctimas por país y grupo |

## Pendientes antes de publicarlo como sitio oficial

- Revisar los términos de uso de ransomware.live y Exploit-DB para uso comercial.
- Validar con producto los textos de vRx, vRadar y vIntelligence del bloque final.
- Las ilustraciones de ese bloque son dibujos propios, no capturas del producto.
- Formulario de contacto: hoy el sitio enlaza a la página de demo; no captura datos.
- Las descripciones de las CVE vienen de la NVD, casi todas en inglés.
