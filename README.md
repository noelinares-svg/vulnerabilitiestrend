# Priorización de vulnerabilidades

Sitio estático que cruza NVD, CISA KEV, EPSS y SSVC con señales de exploit público y asigna una prioridad de P1 a P4.

- `site/`: el sitio (HTML, logos). `data.json` se genera en cada ejecución y no se guarda en el repositorio.
- `scripts/collect.py`: descarga y agrega los datos.
- `.github/workflows/actualizar.yml`: actualiza cada 3 horas y publica en GitHub Pages.

## Puesta en marcha

1. Settings → Pages → Source: **GitHub Actions**.
2. Opcional: Settings → Secrets and variables → Actions → `NVD_API_KEY` (clave gratuita de la NVD; acelera la recolección).
3. Actions → "Actualizar datos y publicar" → Run workflow.

## En el PC

```
python scripts/collect.py site/data.json
python -m http.server 8000 --directory site
```
