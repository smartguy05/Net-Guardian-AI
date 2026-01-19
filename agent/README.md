# NetGuardian Endpoint Agent

A lightweight monitoring agent that collects system activity from endpoints and sends it to a NetGuardian server.

## Features

- **Process Monitoring**: Detects new processes, captures command lines, identifies suspicious activity
- **Network Monitoring**: Tracks new network connections (TCP/UDP), identifies listening ports
- **File Monitoring** (optional): Monitors access to sensitive files
- **Cross-Platform**: Supports Windows, Linux, and macOS

## Installation

### From Source

```bash
cd agent
pip install -r requirements.txt
```

### As a Service (Linux)

```bash
# Copy to system location
sudo cp netguardian_agent.py /opt/netguardian/
sudo cp agent_config.yaml /opt/netguardian/

# Create systemd service
sudo tee /etc/systemd/system/netguardian-agent.service << EOF
[Unit]
Description=NetGuardian Endpoint Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netguardian
ExecStart=/usr/bin/python3 /opt/netguardian/netguardian_agent.py -c /opt/netguardian/agent_config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable netguardian-agent
sudo systemctl start netguardian-agent
```

### As a Service (Windows)

Use NSSM (Non-Sucking Service Manager) or create a Windows Service wrapper.

```powershell
# Download NSSM from https://nssm.cc/
nssm install NetGuardianAgent "C:\Python312\python.exe" "C:\NetGuardian\netguardian_agent.py -c C:\NetGuardian\agent_config.yaml"
nssm start NetGuardianAgent
```

## Configuration

### Via Configuration File

Copy `agent_config.yaml.example` to `agent_config.yaml` and edit:

```yaml
server_url: https://netguardian.local:8000
api_key: your-api-key-here
poll_interval: 30
monitor_processes: true
monitor_network: true
```

### Via Command Line

```bash
python netguardian_agent.py \
    --server https://netguardian.local:8000 \
    --api-key YOUR_API_KEY \
    --interval 30
```

## Getting an API Key

1. Log into NetGuardian as an admin
2. Go to **Sources** > **Add Source**
3. Select **API Push** as source type
4. Select **Endpoint** as parser type
5. Give it a name (e.g., "Endpoint Agents")
6. Click **Create**
7. Copy the generated API key

## Event Types

The agent sends the following event types:

### Process Events
```json
{
    "event_type": "process",
    "data": {
        "pid": 1234,
        "name": "chrome",
        "path": "/usr/bin/chrome",
        "cmdline": "chrome --flag",
        "user": "user",
        "parent_pid": 1,
        "parent_name": "systemd"
    }
}
```

### Network Events
```json
{
    "event_type": "network",
    "data": {
        "local_ip": "192.168.1.100",
        "local_port": 54321,
        "remote_ip": "8.8.8.8",
        "remote_port": 443,
        "protocol": "tcp",
        "state": "established",
        "process_name": "chrome",
        "process_pid": 1234
    }
}
```

### System Events
```json
{
    "event_type": "system",
    "data": {
        "action": "agent_startup",
        "system_info": {
            "platform": "Linux",
            "hostname": "workstation-01"
        }
    }
}
```

## Security Considerations

- The agent requires elevated privileges to access all process information
- Store the API key securely
- Use HTTPS for server communication
- Consider network segmentation for agent traffic
- The agent only sends data to the configured server

## Troubleshooting

### Agent not sending data
1. Check network connectivity to the server
2. Verify the API key is correct
3. Run with `--debug` flag for verbose logging
4. Check firewall rules

### High CPU usage
1. Increase the poll interval (`--interval 60`)
2. Disable file monitoring if not needed
3. Add noisy processes to the whitelist

### Missing events
1. Ensure the agent is running with sufficient privileges
2. Check that the source is enabled in NetGuardian
3. Verify the parser type is set to "endpoint"

## License

MIT - See main project LICENSE file.
