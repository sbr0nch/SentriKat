# SentriKat - Vulnerability Management Platform

SentriKat is an internal vulnerability management system that automatically downloads and filters the CISA Known Exploited Vulnerabilities (KEV) catalog to show only vulnerabilities affecting your organization's software and services.

## Features

- **Automated CISA KEV Sync**: Daily automatic download of the official CISA KEV JSON feed
- **Product Inventory Management**: Web-based admin interface to manage your software inventory
- **Intelligent Filtering**: Automatically matches CVEs to your products by vendor, product name, and custom keywords
- **Interactive Dashboard**: View filtered vulnerabilities with detailed information
- **Acknowledgement System**: Track which vulnerabilities have been reviewed
- **Ransomware Indicators**: Highlight vulnerabilities used in ransomware campaigns
- **REST API**: Programmatic access to all data
- **Search & Filter**: Find specific vulnerabilities quickly
- **Sync History**: Track sync operations and status

## Architecture

- **Backend**: Python 3.11 + Flask
- **Database**: SQLite (upgradeable to PostgreSQL)
- **Frontend**: Bootstrap 5 + JavaScript
- **Scheduler**: APScheduler for daily automated syncs
- **Deployment**: Docker + docker-compose

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone <repository-url>
cd SentriKat
```

2. Create environment configuration:
```bash
cp .env.example .env
# Edit .env and set your SECRET_KEY
```

3. Start the application:
```bash
docker-compose up -d
```

4. Access the application:
- Open http://localhost:5000 in your browser
- Go to Admin panel to add your products
- Click "Sync Now" to download CISA KEV data

### Manual Installation

1. Install Python 3.11+ and create virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment:
```bash
cp .env.example .env
# Edit .env and set your SECRET_KEY
```

4. Run the application:
```bash
python run.py
```

5. Access at http://localhost:5000

## Usage Guide

### Adding Products

1. Navigate to **Admin** panel
2. Click **Add Product**
3. Fill in product details:
   - **Vendor**: Manufacturer name (e.g., Microsoft, Cisco, Apache)
   - **Product Name**: Software name (e.g., Windows Server, IOS, Tomcat)
   - **Version**: Optional version number
   - **Keywords**: Comma-separated additional search terms
   - **Description**: Internal notes
   - **Active**: Enable/disable tracking

Example products:
- Vendor: "Microsoft", Product: "Exchange Server", Keywords: "Exchange"
- Vendor: "Cisco", Product: "IOS", Keywords: "Catalyst, Switch"
- Vendor: "Apache", Product: "Tomcat", Keywords: "Java"

### Viewing Vulnerabilities

1. Go to **Dashboard**
2. View statistics at the top:
   - Total vulnerabilities in CISA KEV
   - Matches for your products
   - Unacknowledged items
   - Products being tracked

3. Use filters to narrow results:
   - CVE ID search
   - Vendor filter
   - Ransomware only
   - Unacknowledged only

4. Review vulnerability details:
   - CVE ID and name
   - Affected vendor/product
   - Description and required action
   - Due date
   - Match reason

5. Acknowledge vulnerabilities after review

### Syncing Data

**Automatic Sync**: Runs daily at 2:00 AM (configurable in .env)

**Manual Sync**:
- Click **Sync Now** button in navigation bar
- Triggers immediate download and processing
- Updates all matches automatically

## API Documentation

### Products

- `GET /api/products` - List all products
- `POST /api/products` - Create product
- `GET /api/products/{id}` - Get product details
- `PUT /api/products/{id}` - Update product
- `DELETE /api/products/{id}` - Delete product

### Vulnerabilities

- `GET /api/vulnerabilities` - List vulnerabilities with filters
  - Query params: `product_id`, `cve_id`, `vendor`, `product`, `ransomware_only`, `acknowledged`
- `GET /api/vulnerabilities/stats` - Get statistics

### Matches

- `POST /api/matches/{id}/acknowledge` - Acknowledge match
- `POST /api/matches/{id}/unacknowledge` - Unacknowledge match

### Sync

- `POST /api/sync` - Trigger manual sync
- `GET /api/sync/status` - Get last sync status
- `GET /api/sync/history` - Get sync history

## Configuration

Edit `.env` file or set environment variables:

```bash
# Security
SECRET_KEY=your-random-secret-key

# Database
DATABASE_URL=sqlite:///sentrikat.db

# CISA KEV Feed
CISA_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# Sync Schedule (24-hour format)
SYNC_HOUR=2
SYNC_MINUTE=0
```

## Deployment

### Production Deployment with Docker

1. Set strong SECRET_KEY in .env:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

2. Update docker-compose.yml for your environment:
```yaml
ports:
  - "80:5000"  # Or use reverse proxy
volumes:
  - /path/to/persistent/data:/app/data
```

3. Deploy:
```bash
docker-compose up -d
```

### Using Reverse Proxy (Nginx)

```nginx
server {
    listen 80;
    server_name vulnerabilities.yourcompany.internal;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### PostgreSQL Database

For production, consider PostgreSQL:

```bash
# Update .env
DATABASE_URL=postgresql://user:password@localhost/sentrikat

# Install PostgreSQL adapter
pip install psycopg2-binary
```

## Matching Algorithm

SentriKat matches vulnerabilities to products using:

1. **Vendor Matching**: CVE vendor contains your product vendor
2. **Product Matching**: CVE product contains your product name
3. **Keyword Matching**: Keywords appear in CVE vendor or product
4. **Cross Matching**: Vendor in product field or vice versa

Matching is case-insensitive and uses substring matching for flexibility.

## Troubleshooting

### Sync Fails

- Check internet connectivity
- Verify CISA KEV URL is accessible
- Check logs: `docker-compose logs -f sentrikat`

### No Matches Found

- Verify products are marked as "Active"
- Check vendor/product names match CVE format
- Add keywords for better matching
- Manually trigger sync after adding products

### Database Locked

- SQLite may lock under high concurrency
- Consider upgrading to PostgreSQL for production

## Maintenance

### Backup Database

```bash
# Docker
docker-compose exec sentrikat cp /app/data/sentrikat.db /app/data/sentrikat_backup.db

# Manual
cp sentrikat.db sentrikat_backup.db
```

### View Logs

```bash
# Docker
docker-compose logs -f

# Manual
# Logs printed to stdout
```

### Update Application

```bash
git pull
docker-compose down
docker-compose build
docker-compose up -d
```

## Security Considerations

- Run behind firewall (internal use only)
- Set strong SECRET_KEY
- Regular database backups
- Keep dependencies updated
- Use HTTPS with reverse proxy
- Implement authentication if needed

## Future Enhancements

Potential features to add:

- Email notifications for new high-priority CVEs
- Integration with NVD for additional CVE data
- Asset management integration
- Multi-user authentication and roles
- Custom severity scoring
- Export reports (PDF, CSV, Excel)
- Slack/Teams notifications
- Jira integration for ticket creation
- Historical trending and analytics
- Bulk product import

## License

Internal use only - customize as needed for your organization.

## Support

For issues or questions, contact your internal security team.

## Credits

Vulnerability data provided by CISA: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
