# TODO & Roadmap

*(A living list of enhancements and fixes for MyScraper – highest priority items first.)*

1. **Streamline User Signup & Authentication:** *Priority: High.*
   The current dashboard requires an admin to pre-register recipient emails, and “login” for normal users is passwordless (just email). We plan to implement a proper user registration flow – for example, allowing new users to request access directly in the UI. This could include an email verification step or an approval mechanism by the admin. The goal is to make onboarding new notification subscribers smoother (and more secure) without manual admin work.

2. **Improved User Session Security:** *Priority: High.*
   At the moment, regular users are “authenticated” simply by storing their email in localStorage after login (no JWT or password). We want to introduce a secure token-based session for users similar to the admin JWT. This might involve issuing a one-time login link via email or a magic code to enter, ensuring that only the owner of an email can manage its subscriptions. It’ll prevent sneaky individuals from simply typing someone else’s email and accessing their subscription settings.

3. **Re-enable/Enhance SMS Notifications:** *Priority: Medium.*
   We started with SMS alerts via Fast2SMS (hence the vestigial code in `notifications.py`), but currently emails are the default. A to-do is to bring back SMS support in a configurable way – perhaps abstracting notifications so users can opt for email **and/or** SMS. This could involve integrating a more globally accessible SMS API (Fast2SMS is India-specific; maybe Twilio or another service for international users). The idea is to let users choose how they want to be notified (and maybe even multiple channels for the truly paranoid stock hunters).

4. **Dynamic Schedule Control via UI:** *Priority: Medium.*
   Right now, the web dashboard shows whether the GitHub Actions workflow is enabled, and we envision a toggle button for turning it on/off (using the `GH_TOKEN` with `workflow` scope). Implementing that toggle is on the roadmap. This will let the admin pause the monitoring when not needed (e.g., you got your lassi, finally!) and resume it later – all from the browser. No need to dig into GitHub settings.

5. **Multiple Product Categories / Site Expansion:** *Priority: Low/Exploratory.*
   Today, the scraper logic is tailored to Amul’s store layout (specific selectors for “Sold Out” alerts, etc.). A longer-term improvement is to make the product checking more modular or even support other websites. This could mean abstracting the `scraper.check_product_availability()` to handle different page structures. It’s a larger effort (essentially turning this into a multi-site scraper), so it’s a back-burner idea for now. A more achievable interim step is to make the selectors configurable per product or per site via the config or UI.

6. **Refactor KV Data Layer (Subscriptions & Recipients):** *Priority: Medium.*
   The Vercel KV usage is straightforward but currently treats data as simple arrays. We might refactor how subscription data is stored and retrieved – for example, indexing by product\_id or recipient\_id for faster lookup, especially if the list grows. Also, some duplicate logic across the API routes (e.g., adding a product also needs to check and update subscriptions) could be streamlined. A more robust approach (if scaling up) might involve moving to a dedicated database (SQLite, Postgres, etc.) or an ORM, but that’s only if needed. For now, some cleanup in how we handle the in-memory structures in code is planned.

7. **UI/UX Polishing:** *Priority: Medium.*
   While the dashboard is functional, there’s always room for polish. A few things on the list:

   * Better responsive design for mobile users (the current layout is desktop-focused, and some elements might overflow on small screens).
   * Visual indicators for subscription status – e.g., a badge or color if a product is currently in stock or how long ago it was last checked (maybe using the data from the last run).
   * Inline help tooltips or a quick tutorial for new users so they understand how to use the dashboard (for example, explaining what “paused” means or what the time window does).
   * Possibly a dark mode (for those 2 A.M. stock-check vibes 🌙).

8. **Artifact Management & Insights:** *Priority: Low.*
   Each run produces screenshots and logs. Over time, lots of runs = lots of artifacts. We might add a feature to auto-prune old artifacts or summarize historical data. An idea is to display a chart of how many times an item went in/out of stock over a period, using past run data. This is a “nice to have” analytics feature that could live on the DeepWiki page or the dashboard (e.g., “Lassi was in stock 3 times in the last month, for an average of 15 minutes each time.”). Implementing this would require storing more historical info (beyond the latest runs) and is thus lower priority until core features are solid.

9. **Code Refactoring & Cleanup:** *Priority: Low.*
   As the project has grown from a single script to a mini web app, there are places to refactor:

   * Simplify `check_stock.py` if possible – maybe break it into smaller functions or classes (one handling fetching subscriptions, one for notifying, etc.). Right now it’s procedural but getting lengthier.
   * Remove any dead code or outdated comments (there are a few “REMOVED” or “OLD” notations especially in the JS). Cleaning those up will make maintenance easier.
   * More docstrings and comments for maintainers. (We’re adding a lot of documentation in README, but in-code explanations are always good for future contributors or the forgetful author 😜.)

10. **Testing & CI Improvements:** *Priority: Low.*
    Introduce some form of testing pipeline. For example, a dry-run mode for the scraper that hits a mock page or uses saved HTML to verify that our selectors and logic still work. This could be integrated into a CI step. It’s tricky because the core of this project interacts with a live site, but even a basic check to ensure none of the modules break on import or that the web API routes return expected dummy responses would be nice to have. This would catch issues early when making changes.

11. **Documentation Updates:** *Priority: Ongoing.*
    Ensure that as features are added or changed, all docs (README, this TODO list, structure doc, DeepWiki page) are kept up-to-date. A future plan is to possibly generate a small wiki or use GitHub Pages for a documentation site if the project gets more complex. For now, maintaining clarity in the markdown files is the plan.

*Feel free to suggest additional todos or pick up any of the above to work on – contributions are welcome! This list can evolve based on user feedback and the ever-changing nature of Amul’s stock antics.* 😄
