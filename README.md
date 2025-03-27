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
   git clone https://github.com/maui1911/oauth_test_app.git
   cd oauth-test
   ```

2. Set up environment variables:
   ```bash
   cp .env.example .env
   ```
   
   Edit the `.env` file with your OAuth configuration:
   ```env
   # OAuth Configuration
   VITE_OAUTH_BASE_URL=https://your-oauth-server.com
   VITE_OAUTH_CLIENT_ID=your_client_id
   VITE_OAUTH_CLIENT_SECRET=your_client_secret
   VITE_OAUTH_REDIRECT_URI=http://localhost:3000/callback
   VITE_OAUTH_PROTECTED_RESOURCE=https://your-oauth-server.com/api/resource
   ```

   Required Environment Variables:
   - `VITE_OAUTH_BASE_URL`: The base URL of your OAuth server
   - `VITE_OAUTH_CLIENT_ID`: Your OAuth client ID
   - `VITE_OAUTH_CLIENT_SECRET`: Your OAuth client secret
   - `VITE_OAUTH_REDIRECT_URI`: The callback URL for the Authorization Code flow (default: http://localhost:3000/callback)
   - `VITE_OAUTH_PROTECTED_RESOURCE`: The URL of your protected resource endpoint

3. Install dependencies:
   ```bash
   npm install
   ```

4. Start the development server:
   ```bash
   npm run dev
   ```

The application will be available at `http://localhost:3000`.

## Docker Deployment

1. Make sure you have created and configured the `.env` file as described above.

2. Build and run with Docker Compose:
   ```bash
   docker compose up --build
   ```

   Or build and run manually:
   ```bash
   docker build -t oauth-test-app .
   docker run -p 3000:80 oauth-test-app
   ```

## Configuration

The application allows you to configure OAuth settings through:
1. Environment variables (recommended for deployment)
2. UI settings panel (useful for testing different configurations)

All settings are persisted in localStorage when changed through the UI.

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