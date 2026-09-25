import { useEffect, useRef } from 'react';
import { useAuth } from '../hooks/useAuth';

/**
 * Renders Google's own "Sign in with Google" button via Google Identity
 * Services (GIS) and forwards the resulting ID token to the backend.
 *
 * Requires the GIS script in your HTML:
 *   <script src="https://accounts.google.com/gsi/client" async defer></script>
 *
 * And VITE_GOOGLE_CLIENT_ID set to the same client ID as the backend's
 * GOOGLE_CLIENT_ID — they must match or verifyIdToken() on the backend
 * will reject every token.
 */
export default function GoogleLoginButton({ onSuccess, onError }) {
  const buttonRef = useRef(null);
  const { loginWithGoogle } = useAuth();

  useEffect(() => {
    if (!window.google) {
      console.error('Google Identity Services script not loaded.');
      return;
    }

    window.google.accounts.id.initialize({
      client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID,
      callback: async (response) => {
        try {
          const user = await loginWithGoogle(response.credential);
          onSuccess?.(user);
        } catch (err) {
          onError?.(err);
        }
      },
    });

    window.google.accounts.id.renderButton(buttonRef.current, {
      theme: 'outline',
      size: 'large',
      width: 280,
    });
  }, [loginWithGoogle, onSuccess, onError]);

  return <div ref={buttonRef} />;
}
