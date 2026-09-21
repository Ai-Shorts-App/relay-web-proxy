# Relay Proxy

A small Node.js web relay for development, testing, and other authorized use.

## Run

```bash
npm install
npm start
```

Open <http://localhost:3000>.

The server blocks localhost, private IP ranges, metadata-style local targets, unsupported protocols, oversized responses, and excessive request rates. It is not intended to be deployed as an anonymous public proxy without adding authentication, stronger abuse controls, and operational monitoring.
