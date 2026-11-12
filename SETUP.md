# Setup: Phase 1 (database + login)

Cloudflare menus change from time to time, so the names below may differ slightly.

## 1. Create the database
1. Cloudflare dashboard → **Storage & databases → D1 SQL database → Create database**. Name it `diet-sms-db`.
2. Open the database → **Console** tab. Paste the whole of `schema.sql` and run it.
3. Copy the **Database ID** (shown on the database page) and paste it into `wrangler.toml` in place of `PASTE-YOUR-DATABASE-ID-HERE`.

## 2. Put the code on GitHub
Create a free GitHub repository and upload this folder (not `node_modules`).

## 3. Deploy
1. Dashboard → **Workers & Pages → Create → Import a repository**, choose your repo.
2. Keep the default build settings and deploy. You get an address like `diet-sms.<yourname>.workers.dev`.
3. Open the Worker → **Settings → Variables and Secrets → Add** a **Secret** named `SETUP_KEY` with a long random value. Redeploy if asked.

## 4. Create the first admin (once)
Open `https://<your-address>/setup.html`, enter the `SETUP_KEY`, a Login ID (e.g. `admin`), a name and a password of 8+ characters.
After an admin exists the page refuses further use, and you can delete `SETUP_KEY`.

## 5. Add your data (Admin portal)
1. **Students tab:** import your Excel file (columns `name`, `rollNo`, `class`, `batch`). Each student gets the Login ID shown in the list and the default password `<LoginID>_123`, and must change it at first login.
2. **Subjects**, then **Teachers** (assign a subject when creating, or later from the Subjects tab), then **Timetable**.
3. **Semester tab:** Promote, and clear old attendance.

## What to check after deploying
- Login works for the admin and for a teacher the admin creates.
- **Login speed.** The free plan limits CPU time per request. Passwords use 20,000 PBKDF2 rounds, which is modest on purpose.
  If login fails with a server error on the real site, tell me and I'll lower it.
