# Project Structure & Design 🗂️
[![Repo Size](https://img.shields.io/github/repo-size/tyagishubham177/MyScraper)](https://github.com/tyagishubham177/MyScraper)

This repo combines a small Python backend with a Node/JavaScript dashboard. Below is a quick tour of the layout and what each part does.

For more details [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/tyagishubham177/MyScraper)
```
MyScraper/
├── myscraper/
│   ├── check_stock.py
│   ├── scraper.py
│   ├── notifications.py
│   ├── config.py
│   └── __init__.py
├── pyproject.toml
├── .github/  
│   └── workflows/  
│       └── schedule.yml  
└── web/  
    ├── index.html  
    ├── style.css  
    ├── particles.js, vanilla-tilt.min.js, lucide-icons.js  
    ├── api/  
    │   ├── login.js  
    │   ├── user-login.js  
    │   ├── status.js  
    │   ├── runs.js  
    │   ├── run.js  
    │   ├── artifact.js  
    │   ├── logs.js  
    │   ├── products.js  
    │   ├── recipients.js  
    │   └── subscriptions.js  
    └── components/  
        ├── login/ (login.html, login.js, login.css, login-main.js)  
        ├── admin-main/ (admin.html, admin.js)  
        ├── user-main/ (user.html, user.js)  
        ├── recipients-ui/ (recipients-ui.js, recipients-ui.html)  
        ├── products-ui/ (products-ui.js, products-ui.html)  
        ├── subscription/ (subscriptions-ui.js)  
        ├── status/ (status.js)  
        ├── runs/ (runs.js)  
        ├── icons/ (icons.js)  
        ├── particles-config/ (particles-config.js)  
        └── utils/ (utils.js)
```

## Python bits 🐍
- **myscraper/check_stock.py** – orchestrates the run, talks to the dashboard API and decides who gets alerts.
- **myscraper/scraper.py** – uses Playwright to see if the “Add to Cart” button is enabled.
- **myscraper/notifications.py** – builds the email body and fires off SMTP messages.
- **myscraper/config.py** – loads environment variables and constants.
- **pyproject.toml** – project metadata and dependencies.

- **schedule.yml** – runs `python -m myscraper.check_stock` every two hours and uploads screenshots as artifacts.
- **scorecard.yml** – scans the repository for security issues with CodeQL and Scorecard.
- **dependabot.yml** – keeps Python dependencies updated automatically (located at `.github/dependabot.yml`).

All workflows include a `workflow_dispatch` trigger so you can run them manually from the Actions tab for quick testing.

## Dashboard (web/) 🌐
- **index.html** & **style.css** – the simple front end.
- **api/** – serverless functions (login, status, products, recipients, subscriptions). They store data in Vercel KV and query GitHub.
- **components/** – modular JS files for the UI (login modal, admin panel, user panel, etc.).

## How it fits together 🔗
1. The Python script grabs products and subscriptions from the dashboard API.
2. Playwright checks each page and saves screenshots.
3. Notifications are sent if items are in stock.
4. GitHub Actions schedules the script and exposes run artifacts.
5. The web dashboard shows recent runs and lets you manage recipients and products.

That’s the high level! For deeper details peek at the source code and enjoy hacking on it. 🚀
