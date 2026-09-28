import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { OAuthService } from '../services/oauthService';

export function Callback() {
  const navigate = useNavigate();

  useEffect(() => {
    // Errors included: the service keeps the outcome for the main page to show.
    OAuthService.getInstance()
      .completeAuthorization(new URLSearchParams(window.location.search))
      .finally(() => navigate('/'));
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
