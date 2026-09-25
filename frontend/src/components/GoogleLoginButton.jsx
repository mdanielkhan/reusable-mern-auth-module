import { useEffect, useRef } from 'react';
import { useAuth } from '../hooks/useAuth';


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
