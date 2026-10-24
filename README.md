# Home Design — private photo gallery

GitHub Pages (public static frontend) + Supabase Edge Function (server-side authentication) + private Supabase Storage.

## Setup
1. Create a Supabase project on the free plan.
2. Storage → New bucket: `private-photos`; **Public bucket OFF**. Do not add public read policies.
3. Supabase Edge Functions → deploy `supabase/functions/gallery/index.ts` as function named `gallery`. **Disable JWT verification for this function**, since the app uses its own HMAC session. The function verifies the Origin, shared/admin password and signed session itself.
4. Set Edge Function secrets in Supabase dashboard (never commit values):
   - `SUPABASE_URL`: project URL
   - `SUPABASE_SERVICE_ROLE_KEY`: project service_role key (server only)
   - `SHARED_PASSWORD`: strong shared viewing password
   - `ADMIN_PASSWORD`: separate strong admin password
   - `SESSION_SECRET`: random high-entropy string (at least 32 bytes)
   - `ALLOWED_ORIGIN`: `https://ducat595-afk.github.io` (no trailing slash)
5. Edit public `config.js` and replace `YOUR_PROJECT_REF` with your Supabase project ref. This URL is **not** a secret.
6. GitHub repository Settings → Pages → Deploy from a branch → `main` → `/(root)`.
7. Open `https://ducat595-afk.github.io/Home-design/`.

## Security / limitations
- Photos live **only in the private Supabase Storage bucket**, not GitHub. Signed photo URLs expire after five minutes.
- Passwords, service_role key, and HMAC secret are **only** Supabase Edge Function secrets; never put them in config.js, GitHub or Pages.
- Viewer and admin use separate passwords. Admin can upload/delete; viewers can only list/view. Sessions expire after one hour and are held only in memory (reload requires re-login).
- GitHub Pages itself is public. Authorization protects photo API, not the HTML.
- For public internet production use, add rate limiting / brute-force protection to the login endpoint (e.g. an upstream gateway); Origin checks alone are not an authentication defense.
- The list endpoint shows up to 1000 objects; add pagination for larger galleries. Upload limit 8MB per photo; HEIC display depends on browser support.
- The shared password is known by all viewers, so any viewer may share it with others. Signed URLs can be copied during their validity period.
- Free-tier storage, bandwidth and Edge Function limits are subject to Supabase's current pricing.
