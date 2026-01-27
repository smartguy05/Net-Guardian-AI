import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Shield, Loader2, AlertCircle } from 'lucide-react';
import { useOIDCCallback } from '../api/hooks';
import ThemeToggle from '../components/ThemeToggle';

export default function OIDCCallbackPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const oidcCallback = useOIDCCallback();

  useEffect(() => {
    const handleCallback = async () => {
      // Get code and state from URL
      const code = searchParams.get('code');
      const state = searchParams.get('state');
      const errorParam = searchParams.get('error');
      const errorDescription = searchParams.get('error_description');

      // Handle error from Authentik
      if (errorParam) {
        setError(errorDescription || errorParam);
        return;
      }

      // Validate parameters
      if (!code || !state) {
        setError('Missing authorization code or state');
        return;
      }

      // Get stored state and code_verifier from sessionStorage
      const storedState = sessionStorage.getItem('oidc_state');
      const codeVerifier = sessionStorage.getItem('oidc_code_verifier');

      // Clean up sessionStorage
      sessionStorage.removeItem('oidc_state');
      sessionStorage.removeItem('oidc_code_verifier');

      // Validate state (CSRF check)
      if (state !== storedState) {
        setError('Invalid state parameter - possible CSRF attack');
        return;
      }

      if (!codeVerifier) {
        setError('Missing code verifier');
        return;
      }

      try {
        // Exchange code for tokens
        await oidcCallback.mutateAsync({
          code,
          state,
          code_verifier: codeVerifier,
        });

        // On success, navigate to dashboard
        navigate('/dashboard', { replace: true });
      } catch (err) {
        console.error('OIDC callback failed:', err);
        setError('Authentication failed. Please try again.');
      }
    };

    handleCallback();
  }, [searchParams, navigate, oidcCallback]);

  // If there's an error, show error page
  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 via-gray-50 to-white dark:from-zinc-900 dark:via-zinc-800 dark:to-zinc-900 px-4">
        <div className="absolute top-4 right-4">
          <ThemeToggle />
        </div>

        <div className="w-full max-w-md text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-xl bg-danger-100 dark:bg-danger-900/30 mb-4">
            <AlertCircle className="w-10 h-10 text-danger-600 dark:text-danger-400" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
            Authentication Failed
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            {error}
          </p>
          <button
            onClick={() => navigate('/login', { replace: true })}
            className="btn-primary"
          >
            Back to Login
          </button>
        </div>
      </div>
    );
  }

  // Show loading state
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 via-gray-50 to-white dark:from-zinc-900 dark:via-zinc-800 dark:to-zinc-900 px-4">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-md text-center">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-xl bg-primary-600 mb-4">
          <Shield className="w-10 h-10 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
          Completing Sign In
        </h1>
        <p className="text-gray-600 dark:text-gray-400 mb-6">
          Please wait while we verify your authentication...
        </p>
        <div className="flex justify-center">
          <Loader2 className="w-8 h-8 animate-spin text-primary-600 dark:text-primary-400" />
        </div>
      </div>
    </div>
  );
}
