# snat.tech — Portfolio & Lebenslauf

Persönliche Portfolio- und Lebenslauf-Website von **Pawel Kostelnik** (Management Consultant / Externer Berater, Cloud Solution Architect).

🌐 Live: [www.snat.tech](https://www.snat.tech) · [www.snat.space](https://www.snat.space)

## Überblick

Statische, responsive Single-Page-Website (Mobile-First) mit Unterseiten zu den einzelnen Zertifizierungen. Die Seite stellt Fähigkeiten, Lebenslauf, Zertifikate und Kontaktmöglichkeiten dar.

## Tech-Stack

| Bereich | Technologie | Version |
|---|---|---|
| CSS-Framework | Bootstrap | 5.3.8 |
| JavaScript | jQuery | 4.0.0 |
| Icons | Font Awesome | 7.x (inkl. v4-shims für Legacy-Icon-Namen) |
| Typing-Effekt | typed.js | 3.x |
| Karussell | slick-carousel | 1.8.1 |
| Layout | isotope-layout / masonry-layout | 3.0.6 / 4.2.2 |
| Weitere | imagesloaded, jquery-validation, animate.css, waypoints, jquery.localScroll |

Eigene Logik liegt in [assets/js/core.js](assets/js/core.js) (minifiziert: [assets/js/core.min.js](assets/js/core.min.js)).

## Projektstruktur

```
index.html              Haupt-Single-Page-Site
*.html                  Zertifizierungs-Unterseiten (MCP, MCT, ITIL, Prince2, …)
sig.html                E-Mail-Signatur
staticwebapp.config.json  Azure Static Web Apps Konfiguration (Security-Header)
assets/
  css/                  Themes (Themify-Icons, Farbvarianten)
  img/                  Bilder, Logos, Zertifikats-Badges
  js/                   core.js / core.min.js
  plugins/              Vendored Frontend-Bibliotheken
php/                    Kontaktformular-Backend
```

## Lokale Entwicklung

```bash
# Einfacher statischer Server im Projekt-Root
python3 -m http.server 8080
# danach http://localhost:8080/index.html öffnen
```

`core.min.js` nach Änderungen an `core.js` neu erzeugen:

```bash
npx terser assets/js/core.js --compress --mangle -o assets/js/core.min.js
```

## Deployment

Automatisches Deployment über **Azure Static Web Apps** via GitHub Actions
([.github/workflows/azure-static-web-apps-green-forest-01c9e3103.yml](.github/workflows/azure-static-web-apps-green-forest-01c9e3103.yml)).
Ein Push auf `main` löst den Build und das Deployment aus. Sicherheits-Header
(`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) werden über
[staticwebapp.config.json](staticwebapp.config.json) gesetzt.

## Barrierefreiheit & Sicherheit

- Mobile-First, responsives Layout für alle Endgeräte
- Alle Bilder mit `alt`-Texten, `<html lang>` gesetzt
- Externe Links mit `rel="noopener noreferrer"`
- Web-Accessibility-Best-Practices nach [W3C WAI](https://www.w3.org/WAI/tips/designing/)

## Änderungen & Korrekturen

- `index.html`: `robots`-Meta von `nofollow` auf `index, follow` korrigiert;
  Portfolio-Kachel-Titel verlinken nun auf die jeweilige Zertifikatsseite
  (statt die Startseite per AJAX-Modal zu laden); Google-Maps-Skript lädt
  `async` (`loading=async`).
- **Zertifizierungs-Unterseiten** auf den sauberen Template-Stand gebracht:
  defekte englische Navigation (`#resume`/`#blog`) entfernt, Font Awesome 4 →
  Font Awesome 7 (`all.min.css` + `v4-shims`), ungenutztes Google-Maps-Skript
  (mit separat exponiertem API-Key) entfernt, `core.min.js` statt `core.js`,
  verwaistes englisches Kontaktformular/Video-Modal entfernt.

### Offen

- Das **Kontaktformular-Backend** (`php/`) ist auf Azure Static Web Apps nicht
  funktionsfähig (kein PHP-Runtime; dem Formular fehlt zudem das vom PHP erwartete
  CSRF-Feld). Für echten Versand wird eine Azure Function oder ein Dienst wie
  Formspree benötigt.
