# CryptoDetect Monitoring Agent

## Installation

1. **Download and Run** `CryptoDetect-Agent-Setup.exe`
2. **Enter your API key** when prompted:
   - API Key (from registration)
   - System ID is auto-fetched from backend
3. **Agent will start automatically** and run in the background

## Configuration

Configuration is stored at:
```
C:\Users\<YourName>\.cryptodetect\config.json
```

## Metrics Storage

Metrics are stored locally at:
```
C:\Users\<YourName>\.cryptodetect\metrics\
```

Each day creates a new file (max 5-minute window).

## How It Works

1. **Collects metrics** every 5 seconds
2. **Filters processes** (only those using >5% CPU or Memory)
3. **Stores locally** in JSON (rolling 5-minute window)
4. **Sends to backend** every 5 seconds by default
5. **ML analysis** happens on backend
6. **Alerts displayed** if cryptojacking detected

## Uninstall

Go to Control Panel → Programs → Uninstall CryptoDetect Agent

## Support

For issues, contact your system administrator.
