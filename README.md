# Prime Baking web shop

The Prime Baking website with secure checkout through **Paynow** (EcoCash, OneMoney, Visa/Mastercard, ZimSwitch and more).

## How payments stay safe

| Risk | What stops it |
|---|---|
| Stealing card numbers or PINs | They never touch this site. Customers enter them on Paynow's own page or approve on their phone. |
| Editing prices in the browser | The browser only sends product names and quantities. The server works out every price from `catalog.js`. |
| Faking a "paid" message | An order is marked paid only after the server asks Paynow directly, checks Paynow's signature with your secret key, and confirms the amount and order reference match exactly. |
| Underpaying | If Paynow reports a different amount, the order is held as `review` and is not confirmed. |
| Injected scripts (XSS) | A strict Content-Security-Policy blocks any script not served by the site. Customer input is never inserted as HTML. |
| Another website submitting orders (CSRF) | Checkout only accepts JSON from your own domain. |
| Looking up other people's orders | Each order can only be read with a random 256-bit token held by the customer's browser. |
| Spamming checkouts or PIN prompts | Limits per device (10 per 10 min) and per phone number (4 per hour), plus a cap on open orders. |
| Leaked secrets | Paynow keys live only in environment variables, never in the website files. |
| Test mode left on by mistake | The server refuses to start in production with test mode on. |

No website can be guaranteed unhackable. What keeps it safe over time: keep the server updated (`npm audit`, `npm update`), keep the Paynow key secret, use HTTPS, and watch the logs for `AMOUNT MISMATCH` or `Rejected` lines.

## 1. Get Paynow keys

1. Sign up or log in at https://www.paynow.co.zw as a merchant.
2. Go to **Receive Payments → New Integration**, choose **3rd Party / Website**, and copy the **Integration ID** and **Integration Key**.
3. New integrations start in **test mode**. Paynow lifts this once you have tested and asked them to go live.

## 2. Run it on your computer (test mode)

Requires Node.js 20.12 or newer.

```bash
npm install
cp .env.example .env      # then open .env and fill in the values
npm start                 # open http://localhost:3000
```

In `.env` for testing: `PAYNOW_TEST_MODE=true`, `NODE_ENV=development`, `PUBLIC_URL=http://localhost:3000`, `TRUST_PROXY=0`, and `PAYNOW_MERCHANT_EMAIL` set to the email you log in to Paynow with.

Paynow's test phone numbers for EcoCash/OneMoney:

| Number | Result |
|---|---|
| 0771111111 | Success after ~5 seconds |
| 0772222222 | Success after ~30 seconds |
| 0773333333 | Customer cancels |
| 0774444444 | Insufficient balance |

Note: Paynow's confirmation call (to `/api/paynow/result`) can't reach `localhost`. That's fine, because the site also checks with Paynow itself every few seconds while the customer waits.

## 3. Put it online

Any Node.js host works (Render, Railway, Fly.io, a VPS). On Render, for example:

1. Put this folder in a private GitHub repository (the `.gitignore` already keeps `.env` and order data out).
2. Create a **Web Service**: build command `npm install`, start command `npm start`.
3. Add the environment variables from `.env.example` in the dashboard:
   `NODE_ENV=production`, `PAYNOW_TEST_MODE=false`, your live `PAYNOW_INTEGRATION_ID` / `PAYNOW_INTEGRATION_KEY`, `PUBLIC_URL=https://your-domain`, `TRUST_PROXY=1`.
4. Add a **persistent disk** mounted at `/var/data` and set `DATA_DIR=/var/data`, so orders survive restarts.
5. Point your domain at the service. HTTPS is switched on automatically.

`TRUST_PROXY` must be the exact number of proxies in front of the app: 1 on most hosts, 2 if you also put Cloudflare in front, 0 on a bare server.

## 4. See your orders

Paid orders show in your Paynow dashboard (reference starts with `PB-`, with the items in the description). On the server:

```bash
npm run orders           # latest 50 orders
npm run orders -- paid   # paid orders only, with name, phone, address and items
```

Each payment also writes a line like `PAID PB-… $36.50` to the server log.

## Changing products and prices

Edit `catalog.js` (prices are in cents: 550 = $5.50) and restart. The website picks up the new prices automatically. Product photos and descriptions are in `public/app.js` and `public/img/`.

## Files

```
server.js      web server, checkout and Paynow handling
catalog.js     products and prices (the only place prices are set)
store.js       saves orders to data/orders.json
orders.js      prints orders (npm run orders)
public/        the website itself
.env.example   settings template; copy to .env
```

The order store is a single file, suited to one server. If the shop grows to several servers, move orders into a database.
