# 🥤 Amul Lassi Tracker

Amul periodically releases a *High-Protein Rose Lassi* pack that often goes out of stock in minutes. This repository contains a small Python utility and accompanying GitHub Actions workflow that watches the [Amul web store](https://shop.amul.com) for the pack of 30 being available. When the script detects that the product can be added to cart, a message is sent via Fast2SMS so that you can order immediately.

The project was created with the goal of running **for free** using only GitHub Actions. By default the action checks every two hours and uploads screenshots of each run for debugging.

## How it works

1. **check_stock.py** uses [Playwright](https://playwright.dev) to load the product page in a headless browser. It types your pincode, waits for the availability indicators and determines whether the item is in stock.
2. When an "Add to Cart" button is found and the page does not show "Sold Out", the script sends an SMS through the Fast2SMS API. Multiple recipients can be configured via environment variables.
3. Each run saves screenshots inside the `artifacts/` directory. When executed by GitHub Actions these screenshots are uploaded as an action artifact so you can see exactly what the page looked like.

The workflow definition lives in `.github/workflows/schedule.yml` and runs every two hours (`cron: "0 */2 * * *"`). You can also trigger it manually from the Actions tab.

## Getting started

1. **Clone the repository and install dependencies**
   ```bash
   git clone https://github.com/<you>/amul-lassi-tracker.git
   cd amul-lassi-tracker
   pip install -r requirements.txt
   ```
   Playwright needs browser binaries so run `playwright install chromium` if you plan to execute the script locally. The GitHub Actions workflow also installs only Chromium to speed up jobs.

2. **Set up environment variables**
   - `PINCODE` – the postal code used on the Amul store.
   - `F2S_API_KEY` – your Fast2SMS authentication key.
   - `F2S_NUMBERS` – comma separated list of phone numbers to notify (e.g. `91xxxxxxxxxx`).
   These can be placed in a `.env` file or configured as GitHub secrets when using the workflow.

3. **Run locally**
   ```bash
   python check_stock.py
   ```
   The script prints each step and saves screenshots to the `artifacts/` folder.

4. **Run via GitHub Actions**
   - Fork this repository or push it to your own account.
   - Add the above variables as secrets in your GitHub project.
   - The `Amul Watchdog` workflow will check every two hours and upload screenshots from each run.

## Optional web interface

The `web/` folder contains a very small HTML page and several API endpoints that can be deployed to [Vercel](https://vercel.com). The page shows recent workflow runs and displays whether the scheduled GitHub Action is enabled.

### Deploying the UI

1. Push your copy of this repository to GitHub.
2. Create a new Vercel project and import the repo.
3. In Vercel, set the environment variables:
   - `GH_REPO` – `<owner>/<repo>` pointing to your GitHub repository.
   - `GH_TOKEN` – a token with the `workflow` scope so the API can toggle the workflow.
   - `GH_WORKFLOW` – workflow filename, defaults to `schedule.yml`.
   - `ADMIN_EMAIL` – admin login email.
   - `ADMIN_PASSWORD_HASH` – bcrypt hash of the admin password.
   - `JWT_SECRET` – secret used to sign admin session tokens.
4. Deploy the project. Visiting the deployed URL will show the workflow status and recent runs.

## Files

- `check_stock.py` – main Playwright script that performs the stock check and sends notifications.
- `requirements.txt` – Python dependencies: `playwright`, `beautifulsoup4` and `requests`.
- `.github/workflows/schedule.yml` – GitHub Actions workflow that installs dependencies, runs the script and uploads screenshots.
- `web/` – optional Vercel front‑end for monitoring the workflow.

With this setup you can monitor Amul's store for the elusive lassi pack and get an instant alert on your phone as soon as it becomes available.
