# CVETodo Agent

The CVETodo Agent is a cross-platform scanner that monitors your systems for installed software packages and
reports them back to your dashboard at https://cvetodo.com. The CVETodo system then keeps a constant watch on any
CVEs related to that inventory and immedatly alerts you to any vulnerabilties plus added them to the ToDo list on your
dashboard.

The source code to the agent is open for anyone to view on Github to ensure transparency in the activies the agent performs.

## Features

- **Multi-platform package scanning**: Supports Windows, Debian/Ubuntu (dpkg), RedHat/CentOS/SUSE (rpm), Python (pip), and Node.js (npm) packages
- **Continuous monitoring**: Run as a service to continuously monitor for new vulnerabilities
- **Flexible configuration**: YAML configuration with environment variable support
- **Structured logging**: JSON and text format logging with configurable levels
- **Offline capability**: Stores scan results locally when API is unavailable
- **Cross-platform**: Runs on Linux, Windows, and macOS
- **Team integration**: Integrates with CVETodo team management and API keys

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/aecwalker/CVETodo-agent/releases).

#### Linux
```bash
wget https://github.com/aecwalker/CVETodo-agent/releases/latest/download/cvetodo-agent-linux-amd64.tar.gz
tar -xzf cvetodo-agent-linux-amd64.tar.gz
sudo mv cvetodo-agent /usr/local/bin/
```

#### Windows
Download `cvetodo-agent-windows-amd64.zip`, extract, and add to your PATH.

#### macOS
```bash
wget https://github.com/aecwalker/CVETodo-agent/releases/latest/download/cvetodo-agent-darwin-amd64.tar.gz
tar -xzf cvetodo-agent-darwin-amd64.tar.gz
sudo mv cvetodo-agent /usr/local/bin/
```

### Build from Source

#### Prerequisites
- Go 1.21 or later
- Make (optional, for build automation)

#### Build Steps
```bash
git clone https://github.com/aecwalker/CVETodo-agent.git
cd CVETodo-agent

# Build for current platform
make build

# Or build for all platforms
make build-all

# Install locally
make install
```

## Configuration

### Interactive Setup
```bash
cvetodo-agent config init
```

This will guide you through an interactive setup process:
```
CVETodo Agent Configuration Setup
=================================

To obtain your API key and team ID:
1. Log into your CVETodo account
2. Navigate to your team settings
3. Go to the 'Agent Keys' section
4. Generate a new API key for this agent

Enter your CVETodo team API key: your-actual-api-key
Enter your CVETodo team ID: your-actual-team-id

Configuration file created at: /home/user/.cvetodo-agent.yaml
You can now run 'cvetodo-agent scan' to perform your first vulnerability scan.
```

If a configuration file already exists, you'll be prompted to replace it:
```bash
cvetodo-agent config init
# Configuration file already exists at: /home/user/.cvetodo-agent.yaml
# Do you want to replace it? (y/N): y
# Replacing existing configuration...
```

To force overwrite without prompting:
```bash
cvetodo-agent config init --force
```

The command creates a configuration file at `~/.cvetodo-agent.yaml` with your actual credentials.

### Check Configuration Status
```bash
cvetodo-agent config status
```

This command helps you troubleshoot configuration issues:
```
Configuration Status
===================

✓ Config file exists: /home/user/.cvetodo-agent.yaml
✓ Configuration is valid
  - API Base URL: https://api.cvetodo.com
  - Team ID: team_12345
  - API Key: sk12****5678 (hidden)
  - Agent Name: my-server
  - Scan Interval: 1h0m0s
  - Enabled Scanners: [dpkg rpm pip npm]
```

### Getting API Keys
To obtain your API key and team ID:
1. Log into your CVETodo account
2. Navigate to your team settings
3. Go to the "Agent Keys" section
4. Generate a new API key for the agent
5. Copy the API key and team ID when prompted during `config init`

### Configuration File
After running `config init`, your configuration file will look like:
```yaml
# CVETodo Agent Configuration
api:
  base_url: "https://cvetodo.com"
  api_key: "your-actual-api-key"
  team_id: "your-actual-team-id"
  timeout: "30s"

agent:
  name: "my-server"
  scan_interval: "1h"
  report_interval: "24h"
  data_dir: "/home/user/.cvetodo-agent/data"

log_level: "info"
log_format: "text"

scanner:
  enabled_scanners:
    - "dpkg"      # Debian/Ubuntu packages
    - "rpm"       # RedHat/CentOS/SUSE packages  
    - "pip"       # Python packages
    - "npm"       # Node.js packages
```

### Environment Variables
All configuration options can be overridden with environment variables using the `CVETODO_` prefix:

```bash
export CVETODO_API_API_KEY="your-api-key"
export CVETODO_API_TEAM_ID="your-team-id"
export CVETODO_LOG_LEVEL="debug"
```

## Usage

### One-time Scan
```bash
# Perform a single vulnerability scan
cvetodo-agent scan

# Scan with debug logging
cvetodo-agent scan --log-level debug
```

### Continuous Monitoring
```bash
# Run agent in continuous monitoring mode
cvetodo-agent run

# Run with custom configuration file
cvetodo-agent run --config /path/to/config.yaml
```

### Command Line Options
```bash
# Global flags
  -c, --config string      config file (default is $HOME/.cvetodo-agent.yaml)
  -l, --log-level string   log level (debug, info, warn, error) (default "info")
      --log-format string  log format (text, json) (default "text")

# Available commands
  run            Start the CVETodo agent in continuous monitoring mode
  scan           Perform a one-time system scan
  config init    Initialize configuration file (--force to overwrite)
  config status  Check configuration status and validate settings
  version        Show version information
  help           Show help for any command

# Config init specific flags
  --force        Force overwrite existing configuration file
```

## Package Scanners

The agent includes scanners for various package managers:

### Supported Package Managers
- **dpkg**: Debian/Ubuntu packages (`.deb`)
- **rpm**: RedHat/CentOS/SUSE packages (`.rpm`)
- **pip**: Python packages
- **npm**: Node.js packages (global installations)

### Scanner Requirements
- **dpkg**: Requires `dpkg-query` command
- **rpm**: Requires `rpm` command
- **pip**: Requires `pip` or `pip3` command
- **npm**: Requires `npm` command

Scanners are automatically enabled based on availability of required commands.

## System Service

### Linux (systemd)
Create `/etc/systemd/system/cvetodo-agent.service`:
```ini
[Unit]
Description=CVETodo Agent
After=network.target

[Service]
Type=simple
User=cvetodo
Group=cvetodo
ExecStart=/usr/local/bin/cvetodo-agent run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable cvetodo-agent
sudo systemctl start cvetodo-agent
```

### Windows Service
Use tools like NSSM (Non-Sucking Service Manager) to run the agent as a Windows service.

### Docker
```dockerfile
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY cvetodo-agent /usr/local/bin/
COPY config.yaml /etc/cvetodo-agent/
CMD ["cvetodo-agent", "run", "--config", "/etc/cvetodo-agent/config.yaml"]
```

## Development

### Prerequisites
- Go 1.21+
- Make

### Development Setup
```bash
git clone https://github.com/aecwalker/CVETodo-agent.git
cd CVETodo-agent

# Setup development environment
make dev-setup

# Run tests
make test

# Run with coverage
make test-coverage

# Format code
make fmt

# Run linting
make lint
```

### Project Structure
```
CVETodo-agent/
├── cmd/agent/          # Main application entry point
├── internal/
│   ├── agent/          # Core agent logic
│   ├── api/            # CVETodo API client
│   ├── config/         # Configuration management
│   ├── logger/         # Logging utilities
│   └── scanner/        # Package scanners
├── build/              # Build artifacts
├── dist/               # Distribution packages
├── Makefile           # Build automation
├── go.mod             # Go module definition
└── README.md          # This file
```

### Build System
The project uses Make for build automation:

```bash
make help          # Show all available targets
make build         # Build for current platform (creates .exe on Windows)
make build-all     # Build for all platforms
make build-windows # Build Windows .exe specifically
make test          # Run tests
make clean         # Clean build artifacts
make package       # Create release packages
```

**Platform-specific outputs:**
- **Windows**: `build/cvetodo-agent.exe`
- **Linux/macOS**: `build/cvetodo-agent`

**Cross-platform builds:**
- Windows: `dist/windows-amd64/cvetodo-agent.exe`
- Linux: `dist/linux-amd64/cvetodo-agent`
- macOS: `dist/darwin-amd64/cvetodo-agent`

**Windows without Make:**
If you don't have Make installed on Windows, use the provided batch script:
```cmd
build.bat
```
This creates `build/cvetodo-agent.exe` ready to use.

## Security

### API Key Management
- Store API keys securely
- Use environment variables in production
- Rotate keys regularly
- Limit key permissions to minimum required

### Network Security
- Agent communicates over HTTPS
- Validate SSL certificates
- Consider using private networks for API communication

### File Permissions
- Configuration files should have restricted permissions (600)
- Data directory should be accessible only to agent user
- Log files may contain sensitive information

## Troubleshooting

### Common Issues

1. **Configuration not found or invalid**
   ```bash
   # Check configuration status
   cvetodo-agent config status
   
   # If config doesn't exist, create it
   cvetodo-agent config init
   
   # Alternative: use environment variables
   export CVETODO_API_API_KEY="your-api-key"
   export CVETODO_API_TEAM_ID="your-team-id"
   ```

2. **API key validation failed**
   - Verify API key in CVETodo team settings
   - Ensure API key has proper permissions
   - Check team ID matches your CVETodo account

3. **Permission denied on package scanning**
   - Ensure agent runs with appropriate permissions
   - Some package managers require elevated privileges

4. **API connection failures**
   - Check network connectivity
   - Verify API endpoint and credentials
   - Check firewall settings

5. **Scanner not found**
   - Install required package manager tools
   - Check PATH environment variable

### Configuration Troubleshooting

Check your configuration status:
```bash
cvetodo-agent config status
```

Expected output when working correctly:
```
Configuration Status
===================

✓ Config file exists: /home/user/.cvetodo-agent.yaml
✓ Configuration is valid
  - API Base URL: https://api.cvetodo.com
  - Team ID: team_12345
  - API Key: sk12****5678 (hidden)
  - Agent Name: my-server
  - Scan Interval: 1h0m0s
  - Enabled Scanners: [dpkg rpm pip npm]
```

If configuration is missing or invalid:
```
Configuration Status
===================

✗ Config file not found: /home/user/.cvetodo-agent.yaml

To create a configuration file, run:
  cvetodo-agent config init
```

### Debug Mode
```bash
cvetodo-agent scan --log-level debug --log-format json
```

### Logs Analysis
- Check structured logs for error details
- Monitor performance metrics
- Review security events

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- GitHub Issues: [Report bugs and request features](https://github.com/aecwalker/CVETodo-agent/issues)
- Documentation: [Wiki](https://github.com/aecwalker/CVETodo-agent/wiki)
- CVETodo Support: [Contact support](https://cvetodo.com/support)

