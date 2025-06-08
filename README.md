# 🥤 Amul Lassi Tracker

**Zero-rupee GitHub Actions bot** that pings your WhatsApp every time
_Amul High-Protein Rose Lassi (pack of 30)_ flips from “Sold Out” ➜ “Add to Cart”.

## 🔧 Setup (5 mins)

1. **Clone & install**
   ```bash
   git clone https://github.com/<you>/amul-lassi-tracker.git
   cd amul-lassi-tracker
   pip install -r requirements.txt
   ```

2. **Trigger the workflow manually**
   - Open your repository on GitHub and go to the **Actions** tab.
   - Select **Lassi Watchdog** and use the **Run workflow** button.

## 🌐 Web UI on Vercel

This repo includes a small web interface (in `web/`) that can be deployed to [Vercel](https://vercel.com). The page exposes **Enable** and **Disable** buttons and also shows the current workflow status with a **Check status** button.

### Deploy steps
1. Push this repository to your own GitHub account.
2. Create a new Vercel project and import the repo.
3. In the Vercel dashboard, define the following environment variables:
   - `GH_REPO` – `<owner>/<repo>` name of this repo.
   - `GH_TOKEN` – a GitHub token with `workflow` scope.
   - `GH_WORKFLOW` – name of the workflow file (defaults to `schedule.yml`).
4. Deploy. Visiting the deployed URL will show a page to enable or disable the workflow.
