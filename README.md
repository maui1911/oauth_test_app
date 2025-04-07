# OAuth 2.1 Test Application

A modern React application for testing OAuth 2.1 flows, built with TypeScript and Tailwind CSS. This application supports both Authorization Code Flow (with PKCE) and Client Credentials Flow.

## Features

- 🔐 Support for OAuth 2.1 flows:
  - Authorization Code Flow with PKCE
  - Client Credentials Flow
- 🛠️ Configurable OAuth settings through web UI
- 💾 Token persistence
- 🔄 Automatic token refresh
- 🎨 Modern UI with Tailwind CSS
- 🐳 Docker support

## Prerequisites

- Node.js >= 18.0.0
- npm or yarn
- Docker (optional, for containerized deployment)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/maui1911/oauth_test_app.git
   cd oauth-test
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

The application will be available at `http://localhost:3000`.

## Docker Deployment

Build and run with Docker Compose:
```bash
docker compose up --build
```

Or build and run manually:
```bash
docker build -t oauth-test-app .
docker run -p 3000:80 oauth-test-app
```

## Configuration

The application allows you to configure OAuth settings through the web UI. All settings are persisted in localStorage and include:

- Base URL: The base URL of your OAuth server
- Client ID: Your OAuth client ID
- Client Secret: Your OAuth client secret
- Redirect URI: The callback URL for the Authorization Code flow
- Protected Resource: The URL of your protected resource endpoint
- Scope: The OAuth scope (default: "openid profile email")

To configure your OAuth settings:
1. Click the "Edit Settings" button in the OAuth Settings panel
2. Enter your OAuth configuration details
3. Click "Save Changes" to apply the settings

You can also reset to default settings using the "Reset to Default" button.

## Development

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build

## Project Structure

```
├── src/
│   ├── components/     # React components
│   ├── services/      # OAuth service implementation
│   ├── config/        # Configuration files
│   └── App.tsx        # Main application component
├── public/           # Static files
├── Dockerfile        # Docker configuration
├── nginx.conf        # Nginx configuration for production
└── docker-compose.yml # Docker Compose configuration
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the ISC License - see the LICENSE file for details. 