# vicarego
[![Build and Release](https://github.com/aschiffler/vicarego/actions/workflows/release.yml/badge.svg)](https://github.com/aschiffler/vicarego/actions/workflows/release.yml)

A Go application to poll data from the Viessmann ViCare API and publish it to an MQTT broker. It uses the OAuth 2.0 PKCE flow for authentication.

## Endpoints
* POST https://iam.viessmann-climatesolutions.com/idp/v3/authorize?client_id={clientId}&code_challenge={code}&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A4200%2F&response_type=code&scope=offline_access
* POST https://iam.viessmann-climatesolutions.com/idp/v3/token
* GET https://api.viessmann-climatesolutions.com/iot/v2/equipment/installations?includeGateways=true
* GET https://api.viessmann-climatesolutions.com/iot/v2/features/installations/{installation}/gateways/{gatewaySerial}/devices/{deviceId}/features

## Features

- Authenticates with the Viessmann API using your credentials.
- Automatically handles access token refreshing.
- Discovers all available features for your installation(s) on startup.
- Periodically polls specified features for their current values.
- Publishes feature data to an MQTT broker with configurable topics.
- Can be run as a systemd service for continuous operation.

## Configuration

The application is configured using environment variables. You can place a `.env` file in the same directory as the executable for convenience.

### Required Variables

| Variable                 | Description                                                                                                                            | Example                                    |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `VIESSMANN_USERNAME`     | Your ViCare account username (email).                                                                                                  | `user@example.com`                         |
| `VIESSMANN_PASSWORD`     | Your ViCare account password.                                                                                                          | `mysecretpassword`                         |
| `VIESSMANN_CLIENT_ID`    | Your Viessmann API client ID. Obtain this from the Viessmann Developer Portal.                       | `xxxxxxxxxxxx`     |
| `VIESSMANN_REDIRECT_URI` | The redirect URI configured for your client ID in the developer (no need to change the default) portal.                                                                | `http://localhost:4200`          |
| `FEATURES_TO_POLL`       | A comma-separated list of feature names you want to poll.                                                                              | `heating.burners.starts,heating.sensors.temperature.outside` |

**Note:** To find the available feature names for `FEATURES_TO_POLL`, run the application once. It will perform an initial discovery and print a list of all features found for your installation.

### Optional Variables

| Variable                   | Description                                                                 | Default     |
| -------------------------- | --------------------------------------------------------------------------- | ----------- |
| `POLLING_INTERVAL_SECONDS` | The interval in seconds for polling data. Minimum is `120`.                 | `120`       |
| `MQTT_BROKER_URI`          | The URI of your MQTT broker. If not set, data will not be published.        | `""`        |
| `MQTT_CLIENT_ID`           | The client ID to use when connecting to the MQTT broker.                    | `vicarego`  |
| `MQTT_USERNAME`            | The username for MQTT broker authentication.                                | `""`        |
| `MQTT_PASSWORD`            | The password for MQTT broker authentication.                                | `""`        |
| `MQTT_TOPIC_PREFIX`        | The prefix for all MQTT topics. The final topic will be `<prefix>/<installationID>/<deviceID>/<featureName>`. | `vicare`    |

### Example `.env` file

```
# Viessmann API Credentials
VIESSMANN_USERNAME=user@example.com
VIESSMANN_PASSWORD=mysecretpassword
VIESSMANN_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
VIESSMANN_REDIRECT_URI=vicare://oauth-callback/everest

# Features to poll
FEATURES_TO_POLL=heating.burners.starts,heating.sensors.temperature.outside,heating.circuits.0.operating.modes.active

# Polling interval
POLLING_INTERVAL_SECONDS=300

# MQTT Configuration
MQTT_BROKER_URI=tcp://192.168.1.100:1883
MQTT_CLIENT_ID=vicarego
MQTT_USERNAME=mqttuser
MQTT_PASSWORD=mqttpass
MQTT_TOPIC_PREFIX=home/vicare
```

## Building from Source

You need to have the Go toolchain installed.

1.  Clone the repository:
    ```sh
    git clone https://github.com/aschiffler/vicarego.git
    cd vicarego
    ```

2.  Build the binary.

    **For amd64 (standard 64-bit Linux/Windows/macOS):**
    ```sh
    go build -o vicarego .
    ```

    **For arm64 (e.g., Raspberry Pi 64-bit OS):**
    ```sh
    GOOS=linux GOARCH=arm64 go build -o vicarego-arm64 .
    ```

## Installation as a systemd Service (Linux)

This guide assumes you are running a Linux distribution with systemd.

1.  **Place the files:**
    -   Move the compiled `vicarego` binary to `/usr/local/bin/`.
    -   Create a `.env` file with your configuration and place it in `/etc/vicarego/config.env`.

    ```sh
    # Assuming you built the binary in the current directory
    sudo mv vicarego /usr/local/bin/
    
    # Create the directory for the environment file
    sudo mkdir -p /etc/vicarego
    
    # Create and edit the environment file
    sudo nano /etc/vicarego/config.env
    ```
    *Paste your configuration variables into this file.*

2.  **Create the systemd service file:**
    Create a new service file at `/etc/systemd/system/vicarego.service`.
    ```sh
    sudo nano /etc/systemd/system/vicarego.service
    ```

    Paste the following content into the file:

    ```ini
    [Unit]
    Description=Viessmann ViCare Polling Service
    After=network-online.target
    
    [Service]
    Type=simple
    ExecStart=/usr/local/bin/vicarego
    EnvironmentFile=/etc/vicarego/config.env
    Restart=on-failure
    RestartSec=10
    
    [Install]
    WantedBy=multi-user.target
    ```

3.  **Enable and start the service:**
    ```sh
    # Reload the systemd daemon to recognize the new service
    sudo systemctl daemon-reload
    
    # Enable the service to start on boot
    sudo systemctl enable vicarego.service
    
    # Start the service immediately
    sudo systemctl start vicarego.service
    ```

4.  **Check the service status and logs:**
    ```sh
    # Check if the service is running
    sudo systemctl status vicarego.service
    
    # View the logs
    sudo journalctl -u vicarego.service -f
    ```
