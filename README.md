[![License](https://img.shields.io/badge/license-Unlicense-blue.svg?logo=unlicense&logoColor=white&style=flat)](http://unlicense.org/)

# 🥤 Amul Tracker

[![Build](https://img.shields.io/github/actions/workflow/status/tyagishubham177/MyScraper/schedule.yml?branch=main&logo=github-actions&logoColor=white&style=flat)](https://github.com/tyagishubham177/MyScraper/actions)
[![Commit](https://img.shields.io/github/last-commit/tyagishubham177/MyScraper?logo=git&logoColor=white&style=flat)](https://github.com/tyagishubham177/MyScraper/commits/main)
[![Quality](https://img.shields.io/codefactor/grade/github/tyagishubham177/MyScraper/main?logo=codefactor&logoColor=white&style=flat)](https://www.codefactor.io/repository/github/tyagishubham177/MyScraper/overview/main)
[![Security](https://api.scorecard.dev/projects/github.com/tyagishubham177/MyScraper/badge?style=flat)](https://scorecard.dev/viewer/?uri=github.com/tyagishubham177/MyScraper)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/tyagishubham177/MyScraper/scorecard.yml?branch=main&logo=github&logoColor=white&style=flat&label=CodeQL)](https://github.com/tyagishubham177/MyScraper/actions/workflows/scorecard.yml)
[![Coverage](https://img.shields.io/codecov/c/github/tyagishubham177/MyScraper?logo=codecov&logoColor=white&label=coverage)](https://codecov.io/gh/tyagishubham177/MyScraper)


**Amul Tracker** is a cheeky little bot that keeps an eye on Amul’s online store so you don’t have to. Specifically, it watches for the elusive *High-Protein Rose Lassi (Pack of 30)* that tends to vanish from stock faster than free doughnuts in the office. When the amul products are back on the menu, this tool **alerts you immediately** – giving you a fighting chance to snag it before it’s gone again. The best part? It runs entirely on free tiers (GitHub Actions and Vercel), so you get round-the-clock monitoring without burning a hole in your pocket.

## Key Features

* ⏰ **Automated Stock Checks:** Leverages [GitHub Actions](https://docs.github.com/en/actions) to run a stock-check script every 2 hours (cron schedule `0 */2 * * *`). No server needed – GitHub’s runners do the heavy lifting for free.
* 🕵️ **Headless Browser Scraping:** Uses [Playwright](https://playwright.dev) to spin up a headless browser and navigate to the product page like a real user. This means it can handle dynamic content (and Amul’s pesky pincode modal) to reliably detect the “Add to Cart” button.
* 📢 **Instant Notifications:** Fires off an alert as soon as the product is in stock. By default, it sends a **fancy email** with the product link and a celebratory message. (The code originally included SMS support via Fast2SMS – you can re-enable it if you’re feeling nostalgic or need text messages 🚀).
* 👥 **Multi-Product & Multi-User Support:** Not limited to lassi – you can configure *any number of products* (as long as they’re on Amul’s shop) to watch. Multiple recipients can subscribe to different products with customizable notification windows (e.g., only get alerts during daytime).
* 💻 **Optional Web Dashboard:** Includes a lightweight web interface (deployable on [Vercel](https://vercel.com) with one click) that lets you:

  * See a live status of the GitHub Action (is the watcher running or snoozing?).
  * View recent check runs and outcomes (including an archive of screenshots for each run).
  * Add or remove products to track, and manage recipient subscriptions without digging into code.
  * Toggle the monitoring on/off (requires admin login) in case you need to pause the chaos.
   
* 📝 **Detailed Logging & Artifacts:** Every run saves a screenshot of the product page (so you know what it looked like when marked in-stock or out-of-stock). There’s also a summary email after each run listing which notifications were sent and which were skipped (and why). It’s like a report card for each cycle.

## Getting Started 🚀

Ready to catch some Lassi? Here’s how to set up the project:

1. **Clone the Repository & Install Dependencies**
   Grab the code and install the required Python packages (preferably in a virtual environment).

   ```bash
   git clone https://github.com/tyagishubham177/MyScraper.git
   cd MyScraper
   pip install -r requirements.txt
   ```

   This will install Playwright, BeautifulSoup4, Requests, Aiohttp, and a few others. *Note:* Playwright needs browser binaries for Chromium – if you plan to run locally, execute:

   ```bash
   playwright install chromium
   ```

   (The GitHub Actions workflow takes care of installing Chromium on the runner, so you only need this step for local runs.)

2. **Configure Environment Variables**
   The script uses certain environment variables for configuration. When running locally, you can put these in a `.env` file at the project root (the code will pick it up via [python-dotenv](https://pypi.org/project/python-dotenv/) if installed, or you can export them in your shell). When using GitHub Actions or Vercel, set these as repository secrets and environment variables respectively.

   * `PINCODE` – Your postal code, used on the Amul store to check availability (e.g. `110001`).
   * `EMAIL_HOST`, `EMAIL_PORT` – SMTP server details for sending email (for example, you can use Gmail’s SMTP or any transactional email service).
   * `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD` – SMTP login credentials.
   * `EMAIL_SENDER` – The sender/from address for notification emails. Also receives the summary emails.
   * `EMAIL_RECIPIENTS` – *(Optional)* A comma-separated list of email addresses to notify by default. In most cases, you won’t set this because notifications are sent per user subscription. If you do set it, everyone here gets notified for every product – use with caution (or maybe just stick to the subscription system!).
   * `F2S_API_KEY` – *(Optional)* Fast2SMS API key for SMS notifications. If provided and if you un-comment the SMS code, the script can send an SMS alert as well.
   * `F2S_NUMBERS` – *(Optional)* Comma-separated phone numbers for SMS (e.g. `91xxxxxxxxxx,91yyyyyyyyyy`).
   * **For the Web Dashboard (if using Vercel):**

     * `GH_REPO` – GitHub repo path in the form `<username>/<repo>` (for your fork if you have one). This is used by the dashboard to query workflow status and runs via GitHub API.
     * `GH_TOKEN` – A GitHub Personal Access Token with `workflow` scope. This is needed to read workflow status, recent runs, and to toggle the workflow on/off from the UI.
     * `GH_WORKFLOW` – The workflow filename to control (defaults to `schedule.yml` if not set).
     * `ADMIN_EMAIL` – The login email for admin access to the dashboard (you choose this).
     * `ADMIN_PASSWORD_HASH` – Bcrypt hash of the admin password. Generate a hash of a strong password and put it here – the dashboard uses it to authenticate you.
     * `JWT_SECRET` – A secret key to sign JWT tokens for the admin session (any random string, the longer the better).
     * *(These last variables are only needed if deploying the web UI on Vercel.)*

3. **Run the Stock Checker Locally (optional)**
   You can execute the Python script directly to verify everything is working:

   ```bash
   python scripts/check_stock.py
   ```

   The script will open a headless browser, navigate to the product page, input the pincode, and report the stock status. You’ll see console logs for each step (e.g., “Page loaded”, “Add to Cart enabled: visible”, etc.), and it will save a screenshot in the `artifacts/` folder. If an item is in stock and you’ve configured email/SMS, it will attempt to send out notifications. (Don’t worry, it also logs if it actually sent or if it skipped due to time windows or missing config.)

4. **Set Up Automated Checks with GitHub Actions**
  The real magic is in automation. By default, this repository includes a workflow file at `.github/workflows/schedule.yml` that is set to run the check every 2 hours. In addition, dependency updates are handled by `.github/dependabot.yml`. To set it up:

   * Fork this repo to your own GitHub account (or push it to a new repo under your account).
   * In your repository settings, add the required secrets (those environment vars from step 2) – at the very least `PINCODE`, and the SMTP settings if you want email alerts. Fast2SMS keys if you use that.
  * GitHub Actions should be enabled by default; if not, enable them. The “Amul Watchdog” and “Scorecard supply-chain security” workflows will run automatically.
  * **Manual trigger:** Both workflows can also be started on-demand from the Actions tab using the **Run workflow** button – handy for testing changes without waiting for the next scheduled run.

5. **(Optional) Deploy the Web Dashboard**
   If you want the fancy dashboard to monitor runs and manage configurations in a nicer way:

   * Have a Vercel account (free tier is fine).
   * Create a new project and select your fork of this repository. Vercel will detect the `web/` directory and deploy it as a static/frontend app with serverless functions. (It’s built to work with the Vercel platform out-of-the-box.)
   * Set the environment variables on Vercel for your project (particularly the `GH_*` ones, `ADMIN_EMAIL`, `ADMIN_PASSWORD_HASH`, etc. from step 2 above). Ensure the variables related to GitHub match your repo and token.
   * Deploy the app. Once deployed, visit the URL. You should see a login screen. Log in with the admin credentials you configured.
   * After login, you’ll see the current status (whether the GitHub Action schedule is active), a list of recent runs with their timestamps and outcomes, and sections to add products or recipients. You can add new product URLs to watch, add recipients (email addresses to notify), and subscribe recipients to products – all through this UI. No coding or manual JSON editing required 🎉.
   * You can also toggle the scheduler on/off (for example, turn it off after you finally secure your lassi stock, and back on when you need it again). The dashboard communicates with GitHub via the token to do this.

## Usage Examples

* **Basic CLI Usage:** The simplest use-case is letting the GitHub Action run and notify you. As long as your secrets are set, you’ll get an email alert saying “🚀 Stock Alert! 🚀 ... *Product Name* is back in stock!” with a link to the product page. If you configured SMS (and uncommented the code for Fast2SMS), you’d get a text like “ALERT: *Product Name* is back in stock!” on your phone as well.
  *(Pro tip: The email template even includes a cheeky “Manage Notifications” link that brings you to the web dashboard, in case you decide you need a break from alerts or want to tweak your notification schedule.)*

* **Subscribing Users to Multiple Products:** Let’s say you and your friends are watching different items (one wants lassi, another wants cheese, etc.). As an admin, add all those products via the dashboard, and add each friend’s email as a recipient. Each friend can then log into the dashboard (using just their email, no password hassle) and subscribe to the products they care about. They can also set a time window – e.g., maybe you don’t want 2 A.M. alerts, so you set your notifications active only between 7 AM and 11 PM. The next time a run finds something in stock, it will only notify those users whose window aligns with the current time. No more 2 A.M. false alarms!
  *(Under the hood: the `subscriptions` allow specifying `start_time` and `end_time` for each user-product combo. The script checks the current time against these before notifying.)*

* **Viewing Logs and Screenshots:** If you want to verify that the script is doing its job correctly, you have a few options:

  * **GitHub Actions Logs:** Go to the Actions run and see the console output – it will show step-by-step what happened, which products were checked, and if notifications were sent or skipped.
  * **Screenshots:** Each run uploads a zip artifact containing screenshots (one per product page checked). You can download it from the Actions run page. If you use the web UI, it lists recent runs and provides direct links to download artifacts and logs. It’s pretty satisfying to see a screenshot with that “Add to Cart” button enabled ✅ or to debug why something might have been considered out-of-stock.
  * **Summary Emails:** If any notifications were sent in a run, the admin (sender address) gets a summary email. It contains a table of all products checked, which emails were notified, and overall status for each product (In stock, Out of stock, or if any notification failed to send). It’s a quick way to review what happened, especially if multiple products are involved.

## Contributing

Contributions are welcome (and encouraged)! This started as a quick personal project to win the battle against blink-and-miss stock, but it’s evolving into a more general tool. If you have ideas for new features, improvements, or you found a bug (uh oh), feel free to open an issue or pull request.

For major changes, it’s good to discuss first – you can reach out via GitHub or the contact links on the web dashboard (there’s a handy “Contact Admin” link that opens an email to the maintainer). Given this project’s playful nature, we especially appreciate contributions that keep things efficient and **light-hearted**.

When contributing code, please follow the existing style:

* For Python: adhere to PEP8 where possible, add comments to explain any complex logic (the script is short, let’s keep it readable).
* For the web UI: it’s plain HTML/JS with Bootstrap 5. Try to keep it modular (see how components are split into their own files). And yes, you *may* add yourself to the list of people who got a lassi because of this tool 😄 (just kidding, maybe).
## Security

Please see [SECURITY.md](SECURITY.md) for information on reporting vulnerabilities.


## License

This project is open-source and available under the **MIT License**. That means you’re free to use, modify, and distribute it. (See the `LICENSE` file for the legalese, if provided, or the DeepWiki page for more info.) In short, play nice and give credit where it’s due.

## Documentation 📚

* [Project structure](StructureReadMe.md) 🗂️
* [Todo & roadmap](ToDoReadMe.md) ✅

## References

* **Amul Online Store:** The target of our affection (and scraping) – [shop.amul.com](https://shop.amul.com). All product names, images, and trademarks are property of Amul. We’re just visiting their site with a bot, please don’t sue us – it’s for a good cause (protein! 💪).
* **Playwright:** The awesome browser automation library that makes this possible. Check it out at [playwright.dev](https://playwright.dev) if you’re curious how it works under the hood.
* **Fast2SMS:** SMS API service used (optionally) for text alerts. More info at their [website](https://www.fast2sms.com/). They have free quotas which is why this project considered them – because who doesn’t like free?
* **GitHub Actions:** The CI/CD platform we bent to our will for scheduling jobs. See GitHub’s docs on [workflow scheduling](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onschedule) if you want to adjust the frequency.

Happy tracking, and may your protein lassi forever be in stock! 🥤🎉
