# OAuth 2.1 Test Application

A modern React application for testing OAuth 2.1 flows, built with TypeScript and Tailwind CSS. This application supports both Authorization Code Flow (with PKCE) and Client Credentials Flow.

## Features

- 🔐 Support for OAuth 2.1 flows:
  - Authorization Code Flow with PKCE
  - Client Credentials Flow
- 🛠️ Configurable OAuth settings
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
   git clone <your-repo-url>
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

1. Build the Docker image:
   ```bash
   docker build -t oauth-test-app .
   ```

2. Run the container:
   ```bash
   docker run -p 3000:80 oauth-test-app
   ```

Alternatively, use Docker Compose:
```bash
docker-compose up --build
```

## Configuration

The application allows you to configure:
- Base URL
- Client ID
- Client Secret
- Redirect URI
- Protected Resource URL
- OAuth Scope

These settings can be modified through the UI and are persisted in localStorage.

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