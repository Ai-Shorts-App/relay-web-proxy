# Relay Proxy

A small Node.js web relay for development, testing, and other authorized use.

## Run

```bash
npm install
npm start
```

Open <http://localhost:3000>.

## Deploy to Vercel

1. Import this GitHub repository in Vercel.
2. Keep the framework preset as `Other` and leave the build command empty.
3. Deploy. Vercel will serve the relay and landing page from the same URL.

The server uses Vercel's serverless runtime when deployed and keeps `npm start` for local use. The relay is intended for authorized use; add authentication and stronger abuse controls before sharing the URL publicly.

The server blocks localhost, private IP ranges, metadata-style local targets, unsupported protocols, oversized responses, and excessive request rates. It is not intended to be deployed as an anonymous public proxy without adding authentication, stronger abuse controls, and operational monitoring.
