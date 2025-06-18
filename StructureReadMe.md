# Project Structure & Design 🗂️

This repo combines a small Python backend with a Node/JavaScript dashboard. Below is a quick tour of the layout and what each part does.

```
MyScraper/
├── check_stock.py
├── scraper.py
├── notifications.py
├── config.py
├── requirements.txt
├── .github/
│   └── workflows/
│       └── schedule.yml
└── web/
    ├── index.html
    ├── style.css
    ├── api/
    └── components/
```

## Python bits 🐍
- **check_stock.py** – orchestrates the run, talks to the dashboard API and decides who gets alerts.
- **scraper.py** – uses Playwright to see if the “Add to Cart” button is enabled.
- **notifications.py** – builds the email body and fires off SMTP messages.
- **config.py** – loads environment variables and constants.
- **requirements.txt** – libraries needed to run the scripts.

## GitHub Actions 🤖
- **schedule.yml** – runs `check_stock.py` every two hours and uploads screenshots as artifacts.

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
