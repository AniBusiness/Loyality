# Loyalty Perks — free deploy on Cloudflare (Workers + D1)

Needs: Node 20+, a free Cloudflare account, this folder on your computer.

1. npm install
2. npx wrangler login
3. npx wrangler d1 create loyalty        -> copy the database_id into wrangler.toml
4. npx wrangler d1 execute loyalty --remote --file=schema.sql
5. npx wrangler secret put JWT_SECRET     (type any long random text)
   npx wrangler secret put ADMIN_KEY      (your private owner key)
6. npx wrangler deploy                    -> gives you https://loyalty-perks.<you>.workers.dev

Add a client store (use your own key and URL):
curl -X POST https://loyalty-perks.<you>.workers.dev/api/super/stores \
  -H "x-admin-key: YOUR_ADMIN_KEY" -H "content-type: application/json" \
  -d '{"slug":"store1","name":"Green Leaf Grocers","emoji":"🌿","goal":6,"color":"#12b76a","pin":"4821"}'
Their link: https://loyalty-perks.<you>.workers.dev/store1   (QR this and print it at the counter)

Own domain: Cloudflare dashboard -> Workers -> loyalty-perks -> Settings -> Domains & Routes.

Local test: npx wrangler d1 execute loyalty --local --file=schema.sql && npx wrangler dev


## How customer login works (free, no SMS/OTP)
- Customer creates a card once: phone number first. New number -> create a password + name/age/gender; known number -> just the password. Afterwards they stay signed in on that phone for 90 days.
- On a new phone they enter their number, then their password.
- Forgot password: staff opens "Staff counter" -> "Reset a customer's password". The customer enters their number and is asked to set a NEW password (within 15 minutes).

## Anti-abuse built in
- Stamps / free items can only be given by staff with the store PIN. Customers can never add or redeem anything themselves.
- Wrong password: 5 tries then a 30-minute lock, doubling on repeated failures (max 24 h). Per-IP limits on login and sign-up too.
- Passwords are stored as keyed hashes; the secret (JWT_SECRET) lives only in Cloudflare, so a leaked database can't be used to guess PINs.
- Login errors never say anything beyond a generic "Wrong password".
- Staff see the customer's first name after each stamp, so they can spot a wrong number.
- Fresh database needed if you used an earlier version: run schema.sql on a new D1 database.
- The first step ("is this number registered?") is rate-limited per IP so numbers can't be mass-checked.
