# Project Structure and Design
This document breaks down the repository structure of **MyScraper (Amul Lassi Tracker)**, explaining the purpose of each major component. The project blends a Python backend (for scraping and notifications) with a lightweight Node/JavaScript frontend (for the optional dashboard). Below is an overview of the layout:

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

Let’s break these down in plain English:

## Root Python Scripts

* **`check_stock.py`:** The main orchestrator of the stock-checking logic. When run (either locally or by the GitHub Actions workflow), this script does the following:

  1. Loads configuration from environment (via `config.py`).
  2. Fetches the list of products to monitor and the list of subscriptions (who wants what notifications) by calling the web API endpoints (if the web UI is deployed) or reading environment variables. Specifically, it calls the local endpoints `GET /api/products`, `GET /api/recipients`, and `GET /api/subscriptions` to get the latest data.
  3. Launches Playwright (headless Chromium) and iterates through each product:

     * For each product URL, it uses `scraper.py` to load the page, handle the pincode modal, and determine stock status (checking if the “Add to Cart” button is enabled and not accompanied by “Sold Out” messages).
     * It reuses the same browser/page for all products in one run to save time (enters pincode once, then skips that step for subsequent products).
     * Takes a screenshot of each page and saves it to `artifacts/` folder (which GitHub Actions will bundle and upload as an artifact).
  4. Determines which subscriptions (user-product pairs) should be notified: it filters out subscriptions that are paused or outside their designated notification time window (`start_time`–`end_time`), and only notifies active ones.
  5. Sends out notifications via email (using `notifications.py`) to all eligible recipients for any product that is in stock. If a product is out of stock, or a subscription is not in the allowed time, it logs that no notification was sent for those.
  6. Records summary info for the run – how many notifications sent, etc. – and if any notifications were sent, triggers a summary email to the admin (so you know that “3 users were notified that Lassi is in stock at 8:00AM”, for example).
  7. Prints logs throughout, which end up in the GitHub Actions log or console output.

* **`scraper.py`:** Contains the `check_product_availability` function, which encapsulates the Playwright browser automation. Key points in this module:

  * It uses Playwright’s async API to launch a browser and open a new page (if one isn’t passed in – the script passes an existing page to reuse).
  * It navigates to the given product URL, waits for network idle (page fully loaded).
  * Handles the **pincode modal**: Amul’s site pops up a location modal. The scraper either skips if we’ve already done it (using a `skip_pincode` flag), or enters the PINCODE (from config) into the modal, selects the suggestion, and waits for the page to refresh with availability info for that location.
  * Once that’s handled, it checks various selectors:

    * Looks for the “Sold Out” alert banner.
    * Checks if the “Add to Cart” button is present and whether it’s disabled.
    * Checks if a “Notify Me” button is present (which also indicates out-of-stock in this context).
    * Determines `in_stock` boolean based on these elements’ visibility (the logic is essentially: if an enabled Add-to-Cart exists and there’s no visible Sold-Out message, we consider it in stock).
  * Extracts the product name from the page (the `<h1>` title of the product) to use in notifications, so that even if the configured name is generic, the alert can say the exact product name.
  * Saves a screenshot of the page to `artifacts/screenshot_<product>.png`.
  * Returns a tuple `(in_stock, product_name)` back to `check_stock.py`.

* **`notifications.py`:** Handles formatting and sending notifications. Main functionality:

  * `format_long_message(product_name, url)`: Returns an HTML string for the email body when a product is in stock. It includes some inline CSS for styling, a big bold product name, a green “View Product Now” button linking to the product page, and a note about how to manage notifications (with a link to the web app).
  * `format_summary_email_body(timestamp, summary_data, total_sent)`: Builds an HTML summary listing each product that was checked, who was notified (if anyone), and statuses (it compiles a table showing “Sent” or reasons for not sending per user). This is used for the admin summary email after each run.
  * `send_email_notification(subject, body, sender, recipients, host, port, username, password)`: A utility that sends an email via SMTP. It constructs a MIME email, connects to the SMTP host, and BCCs all recipients. It prints success or catches exceptions for error logging.
  * There is also a commented-out `send_fast2sms(msg)` function which, if revived, would send an SMS via the Fast2SMS API. It’s currently not used (the project pivoted to primarily use emails), but it’s there as a reference for how one might integrate SMS.

* **`config.py`:** A simple config loader. It pulls in environment variables (like `PINCODE`, email server settings, etc.) and provides them as module-level constants that other modules import. It also defines `URL` for the product (originally the single product URL for lassi) – note that with multi-product support, that specific URL is less critical, since now we use the products list from KV. But it’s likely kept for legacy reasons or a default. It also sets `RUN_OFFSET_MINUTES = 15` (to allow slight flexibility in run timing) and a default `APP_BASE_URL` (which points to the local or deployed web app, defaulting to `http://localhost:3000`). The `APP_BASE_URL` is used by the script to know where to call the `/api/products` and other endpoints.

* **`requirements.txt`:** Lists Python dependencies:

  * `playwright` for browser automation,
  * `beautifulsoup4` (possibly from an earlier version of logic or for potential parsing, though current code doesn’t heavily use it),
  * `requests` for HTTP requests (not heavily used now, since aiohttp and Playwright cover our needs),
  * `aiohttp` for async HTTP calls (used to fetch data from the web app’s API routes),
  * `python-dateutil` and `pytz` for time handling (ensuring correct timezones for the scheduling window logic).

* **`.github/workflows/schedule.yml`:** This is the GitHub Actions workflow file. It defines the automation that makes the project tick:

  * It’s triggered on a cron schedule (every 2 hours) and also allows manual triggers (`workflow_dispatch`).
  * The job it runs basically checks out the repo, sets up Python, installs dependencies (using `pip install -r requirements.txt`), installs Playwright’s Chromium, and then runs `python check_stock.py`.
  * After running the script, it uses actions to upload the `artifacts/` folder as a zip file. This means each run will have an artifact containing all the screenshots taken during that run (if any). The artifact is accessible via the GitHub Actions UI or via our web dashboard’s artifact download feature.
  * The workflow is configured to use Ubuntu and runs with Python 3.x (likely whatever the latest is, since we didn’t pin a version here).
  * Environment vars (like secrets for PINCODE, etc.) are passed into the job via GitHub’s mechanism. So the script has what it needs to run.

## Web Dashboard (Front-end + API)

The `web/` directory contains a minimal front-end app intended to be deployed on Vercel (or could be run locally with a simple server). It’s not a full-fledged React app or anything – it’s mostly static HTML with vanilla JS modules and some serverless function files under `api/`. Here’s how it’s structured:

* **`web/index.html`:** The main HTML page. It loads some external resources (Google Fonts, Bootstrap CSS, and JS libraries like `particles.js` for the fun particle background, `vanilla-tilt.js` for card hover effects, and `lucide-icons.js` for icons). It also links our own `style.css` and the login CSS.
  The body of index.html is mostly an empty shell: it has a `#particles-js` div for the background animation, a `#particles-js-bg` for the gradient overlay, and a `#global-loader` which is a full-page spinner overlay (hidden by default, shown during data loads). Crucially, it does **not** have the main content hard-coded. Instead, it loads the login script as a module:

  ```html
  <script type="module" src="components/login/login-main.js"></script>
  ```

  This kicks off the logic to either show the login screen or, if you’re already logged in, directly load the appropriate content (admin or user view).

* **`web/style.css`:** Some custom styles for the dashboard, such as for the card layout, background, collapsible sections, etc. It complements Bootstrap’s styles.

* **`web/api/`**: This directory contains serverless function files for Vercel. Each file exports a default async function `handler(req, res)` that processes an HTTP request. These act as our backend for the web UI, handling everything from authentication to data management and talking to GitHub’s APIs.

  * **`login.js`:** Handles admin login. It expects a POST with admin email and password, checks them against `ADMIN_EMAIL` and `ADMIN_PASSWORD_HASH` (using bcrypt to compare the hash), and returns a JWT if valid. It also implements rate limiting / lockout – after 3 failed attempts it will start rejecting attempts for an increasing delay (this data is stored in Vercel’s KV under a key). This protects against brute force attempts on the admin login.
  * **`user-login.js`:** Handles user login. This is a similar concept but for normal users (recipients). A user provides just their email (no password). The endpoint checks if that email exists in the `recipients` list in KV. If yes, it returns 200 OK (the front-end then allows them in). If not, it counts that as a failed attempt. After a few failures, it will also lock out for a while, prompting the user to contact admin. Essentially, it’s a gate to ensure random people can’t just add themselves unless approved. The front-end doesn’t get a token for users; it simply uses the success response to proceed.
  * **`status.js`:** Requires admin auth (checks the JWT cookie) and then hits GitHub’s API to get the current state of the Actions workflow (`active` or `disabled`). It uses the `GH_REPO` and `GH_WORKFLOW` env vars to know which workflow to check. This is used to display the big “Monitoring is ON/OFF” indicator on the dashboard.
  * **`runs.js`:** Requires admin auth. Fetches the list of recent workflow runs from GitHub (using the Actions API). We limit to the last 5 runs for brevity. It returns run ID, status, conclusion, timestamps, etc. The dashboard uses this to populate the history of recent checks.
  * **`run.js`:** Requires admin auth. Fetches detailed info for a particular run ID (jobs and steps, and specifically looks for the custom step “Run stock checker” to get its status). It also fetches artifact info for that run. This powers the detail view if we want to drill into a specific run’s results in the UI (like listing all screenshots available for that run, etc.).
  * **`artifact.js`:** Requires admin auth. Given an artifact ID, it fetches the actual artifact ZIP from GitHub and streams it back. This allows the front-end to download screenshots directly by hitting our own API (which proxies from GitHub).
  * **`logs.js`:** Similar to artifact – given a run ID, it fetches the raw logs ZIP from GitHub Actions and returns it. This could be used to download logs or even display them (if we wanted to parse them client-side).
  * **`products.js`:** CRUD for products in KV. This one (and the next two) are the core of how the dashboard manages data:

    * **GET** `/api/products`: returns the list of products (as an array of `{id, name, url}`) sorted by name.
    * **POST** `/api/products`: **admin-only** – adds a new product. It expects `url` and `name` in the body, validates them (ensures URL format is correct and name is not empty), generates a new `id` (just a timestamp string), and saves it. It will reject if a product with the same URL already exists (to avoid duplicates).
    * **PUT** `/api/products?id=...`: **admin-only** – edits an existing product (identified by query param id). Allows updating the name or URL (again validating format). Useful if you made a typo or the site changed URL.
    * **DELETE** `/api/products?id=...`: **admin-only** – removes a product. It also goes and removes any subscriptions related to that product (cascading delete) so you don’t end up with orphan subscriptions.
    * Under the hood, it uses Vercel KV (Upstash Redis) to store a key `products` which holds an array of product objects.
  * **`recipients.js`:** CRUD for recipients (people who will get notifications):

    * **GET** `/api/recipients`: returns the list of all recipients (`{id, email}`).
    * **POST** `/api/recipients`: **admin-only** – adds a new recipient email. It prevents duplicates and requires a valid email format. Generates an `id` (timestamp string).
    * **DELETE** `/api/recipients?id=...`: **admin-only** – deletes a recipient by id, and also removes any subscriptions that belong to that recipient (to avoid dangling subs).
    * Data stored in KV under key `recipients` (array of recipient objects).
  * **`subscriptions.js`:** Management of who subscribes to what:

    * **GET** `/api/subscriptions`: Returns subscriptions. You can filter by `recipient_id` or `product_id` via query params. If no query params, it returns all subscriptions (each subscription is like `{id, recipient_id, product_id, start_time, end_time, paused}`).
    * **POST** `/api/subscriptions`: Adds a new subscription or updates an existing one. *No admin auth required here* – this is intentional so that a normal user can subscribe themselves (once they are a recognized recipient). It expects `recipient_id` and `product_id`, and optional `start_time`, `end_time` (HH\:MM strings) and `paused` (boolean). If a subscription for that user & product already exists, it updates the timing or paused status instead of adding duplicate.
    * **DELETE** `/api/subscriptions`: Removes a subscription (expects recipient\_id and product\_id in the body to identify which one). This is used when a user unsubscribes from a product.
    * Data in KV under key `subscriptions` (array of subs). The code ensures that if a product or recipient is deleted from their respective lists, related subscriptions are cleaned up too.
    * The lack of admin requirement means the front-end has to ensure only legitimate users call these (the front-end will only call with the current user’s own recipient\_id, which is fine, but there isn’t deep auth on the backend for this – this is noted in our TODOs).

  All these API routes use the `kv` import from `@vercel/kv` which gives easy access to the Upstash Redis instance Vercel provides. Data is stored as JSON. The design is simple and works for the scale here (dozens of entries, not thousands).

* **`web/components/`**: This folder contains the front-end modules. Each feature has its HTML, JS, and sometimes CSS split for clarity:

  * **Login component (`login/`):**

    * `login.html` defines the login popup UI – it has two tabs (Admin and User), fields for admin email/password, field for user email, and some messages/links for error states (like “contact admin” links).
    * `login.css` styles the login modal (centered form, etc.).
    * `login.js` contains logic to handle showing the login modal, switching between Admin vs User tabs, capturing input, and calling the respective login APIs. It also handles lockout feedback – e.g., if too many failed attempts, it shows a countdown and a link to email or Reddit PM the admin (yes, there’s a Reddit link configured to message the developer’s Reddit handle, which is a fun touch for support).
    * `login-main.js` is the entry point loaded by index.html. It imports the needed init functions from login.js, particles, icons, etc., and on DOMContentLoaded, it initializes the login process (which will either show the login form or directly redirect to the main app if a valid session exists).
  * **Admin main component (`admin-main/`):**

    * `admin.html` – the HTML for the admin view after logging in. This likely contains the structure for the dashboard: the cards or sections for “Status”, “Recent Runs”, “Products Management”, “Recipients Management”, etc. It probably includes placeholders that the JS will fill in with data from the APIs.
    * `admin.js` – logic exclusive to the admin view, such as binding event handlers to admin-only buttons (like toggling workflow, adding/deleting products or recipients). This JS would be responsible for fetching initial data (e.g., call `/api/status`, `/api/runs`, `/api/products`, `/api/recipients` on load) and then updating the DOM accordingly.
  * **User main component (`user-main/`):**

    * `user.html` – HTML for the user’s view. A user (non-admin) after login probably sees a simpler interface – perhaps a list of products with checkboxes or toggles to subscribe/unsubscribe, and maybe their current subscription status. There might also be a way to pause or set times, etc.
    * `user.js` – the logic for the user dashboard. It would fetch the list of products (to show what can be subscribed to) and the user’s current subscriptions (likely by calling `/api/products` and `/api/subscriptions?recipient_id=<their id>`). Then it handles events like when a user subscribes to or unsubscribes from a product (calling the POST or DELETE on `/api/subscriptions`), or if they adjust the time window or pause status.
  * **Recipients UI (`recipients-ui.js` & `.html`):** Part of admin view – provides the interface to add or remove recipient emails. For example, an admin could enter an email and hit “Add Recipient” (the JS calls POST `/api/recipients`), and the list of current recipients is displayed (with maybe a delete button next to each calling DELETE `/api/recipients`). The HTML likely is a section in the admin page modal or collapsible.
  * **Products UI (`products-ui.js` & `.html`):** Similarly, the interface for admin to manage products. Input fields for product URL and name, add button, list of existing products with edit/delete options. This ties into the `/api/products` routes.
  * **Subscription UI (`subscriptions-ui.js`):** This might handle the interactive bits for user subscriptions (since user-main can list products, this module might handle the toggling and time scheduling UI elements for each subscription). It could also be utilized by admin if they had to view who’s subscribed to what (though likely admin doesn’t micromanage individual subscriptions via UI in this version, and instead it’s user-driven).
  * **Status (`status.js`):** Contains `fetchStatus` which calls `/api/status` to get workflow state and then updates the DOM (e.g., displays “✅ Monitoring Enabled” or a big red “Paused” message). It likely also has a function to toggle state (maybe by calling a non-existent PATCH route or by calling GitHub API directly – this part may be planned).
  * **Runs (`runs.js`):** Contains `fetchRuns` to get recent runs via `/api/runs` and then populates the runs list in the UI. Possibly also handles clicking on a specific run to fetch more details via `/api/run?id=...` and maybe show artifacts or logs links.
  * **Icons (`icons.js`):** Probably initializes the Lucide icon library. Lucide is an icon set; this script might call `lucide.createIcons()` to replace `<i data-lucide="name">` elements with SVGs. This is part of making those pretty icons in buttons or links.
  * **Particles config (`particles-config.js`):** Likely configures the particles.js background (the floating bubbles or shapes you see animating in the background). It probably loads a JSON or sets parameters like number of particles, speed, etc. Purely aesthetic.
  * **Utils (`utils.js`):** Helper functions used by multiple components. For example, `showGlobalLoader()` and `hideGlobalLoader()` to display the loading spinner overlay, or `createRipple()` to show a click ripple effect on buttons (just cosmetic). Any small utility used in various places (like formatting times or so) could live here.

**Data Flow & Design Patterns:**

* **GitHub Actions as Scheduler:** Instead of running a persistent server or cron job on a personal machine, the design cleverly uses GitHub Actions to perform periodic work. This decouples the monitoring from any user’s environment and leverages free compute time. The trade-off is a minimum 1-minute granularity and some complexity in passing data (hence the need to use the Vercel API to fetch subscriptions data). It’s a cost-effective pattern and works well for the use-case (checking every couple hours is fine for something that sells out in minutes but only restocks occasionally).

* **Vercel KV as Database:** The project doesn’t use a traditional database. Instead, it uses Vercel’s Key-Value store (which is essentially Redis under the hood) to persist data like products, recipients, and subscriptions. This is convenient in a serverless context – no separate DB to connect to, and operations are simple get/set of whole objects. It fits the low write, relatively low data volume needs. The code organizes the data as needed (filtering in memory on GET, etc.). For a small app, this is fine and keeps things simple.

* **Separation of Concerns:** Notice how the Python side doesn’t hardcode product info (except a default URL in config). It always reaches out to the web API to get current products and subscriptions. This means the data of “what to check” and “who to notify” is managed by the web component, not by the script’s internal logic. This separation allows updating the watch list and subscribers on the fly via the dashboard without modifying the script code or redeploying anything. The Python script is essentially stateless between runs, always pulling fresh data from the KV store.

* **Asynchronous Operations:** Both the Python script and the Node API make use of async features:

  * Python uses `asyncio` to run the Playwright browser and to perform HTTP requests to the API concurrently. For instance, it could fetch recipients and products at the same time (though the code as written does them sequentially, but uses async/await for simplicity). When checking multiple products, it currently does them one after the other with `await`, but using one browser instance.
  * Node (Vercel functions) uses async/await for all I/O (calls to KV or GitHub). This is standard for Node but important for performance when these endpoints are hit.

* **Auth and Security:** The admin uses JWT cookies to stay logged in on the dashboard (so they don’t have to re-login every time). Normal users do not get a JWT; their “auth” is client-side by remembering the email. This is recognized as an area for improvement. The API endpoints enforce admin-only where appropriate using a helper (`requireAdmin`) that checks the JWT in the request. For user actions like subscribing, the security currently relies on the design that one wouldn’t easily guess another’s recipient ID. It’s somewhat security-through-obscurity and trust — acceptable for a small trusted circle but not robust for a public service (documented in TODOs to be enhanced).

* **UI Design:** The interface uses Bootstrap 5 for layout and components (modal, collapsible sections, buttons, etc.). It’s a single-page app in behavior: content is dynamically loaded into the page after login, rather than doing full page reloads for different views. E.g., once logged in as admin, the script likely fetches `admin.html` and injects it into the DOM (similar to how the login HTML is fetched). This keeps the initial load small and only loads the heavy content for the right user role. The use of modules keeps code organized by feature.

* **Notifications & Windows:** A subtle design feature is the “notification window” per subscription. Each subscription can specify a start and end time. The logic in `check_stock.py` (function `within_time_window`) checks if the current time (IST) falls within that range. If not, the notification for that subscription is skipped. This allows users to, say, silence nighttime alerts. It’s implemented simply by storing two strings `start_time` and `end_time` with default “00:00” to “23:59” (meaning always active unless changed).

* **Artifacts and Logging:** By saving screenshots and sending summary emails, the design leans towards transparency. If something goes wrong or if an alert was missed, the user (or admin) has multiple ways to debug: screenshot of what the site showed, logs of the script’s decisions, and a summary that explicitly states “why” someone was not notified (e.g., “Skipped - Subscription Not Due” if outside their time window, or “Not Sent - Email Config Missing” if email sending wasn’t set up).

* **DeepWiki Reference:** While not part of the code, it’s worth noting that the project has a DeepWiki page (as mentioned in the README references). That likely contains additional context or notes from the developer, acting as an extended documentation or design journal. This isn’t directly used in the code but is part of the project’s knowledge base.

In summary, the **MyScraper** project is organized to separate the concerns of *monitoring logic* (Python script + GitHub Actions) and *configuration/interaction* (Web dashboard + Vercel functions). The structure makes it easy to update what’s being monitored and who gets alerts without touching the core script. The use of free cloud resources (GitHub runners, Vercel serverless + KV) showcases a cost-effective architecture. Each component in the repository plays a role in this symphony:

* The Python code checks stock and sends alerts.
* The GitHub workflow automates the Python runs.
* The web front-end provides control and visibility.
* The Vercel functions connect the front-end, the data store, and external APIs (GitHub, email, etc.).

This modular design allows the project to be quite extensible – you could imagine swapping out the target site (with some changes in `scraper.py`), or adding a new notification method, all without overhauling the whole system.

Happy coding! If you’re looking at this structure to make changes or contributions, we hope this guide clarifies what’s what. Now go forth and keep that Lassi on your radar! 🥤🚀
