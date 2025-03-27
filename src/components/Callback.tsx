import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { OAuthService } from '../services/oauthService';

export function Callback() {
  const navigate = useNavigate();
  const oauthService = OAuthService.getInstance();

  useEffect(() => {
    const handleCallback = async () => {
      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      const state = params.get('state');
      const error = params.get('error');

      if (error) {
        console.error('OAuth error:', error);
        navigate('/');
        return;
      }

      if (!code || !state) {
        console.error('Missing code or state parameter');
        navigate('/');
        return;
      }

      try {
        await oauthService.exchangeCodeForTokens(code, state);
        navigate('/');
      } catch (error) {
        console.error('Failed to exchange code for tokens:', error);
        navigate('/');
      }
    };

    handleCallback();
  }, [navigate]);

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center">
      <div className="bg-white p-8 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Processing OAuth callback...</h2>
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
      </div>
    </div>
  );
} 