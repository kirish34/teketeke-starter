// TekeTeke — Admin Login (CSP safe)
const $ = (id) => document.getElementById(id);

async function redirectIfLoggedIn() {
  try {
    const res = await fetch('/api/auth/me', { credentials: 'include' });
    if (res.ok) {
      window.location.href = '/';
    }
  } catch (_) {
    // ignore
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const username = $('username').value.trim();
  const password = $('password').value;
  const button = $('btn');
  const error = $('err');
  error.textContent = '';

  if (!username || !password) {
    error.textContent = 'Enter username and password';
    return false;
  }

  button.disabled = true;
  button.textContent = 'Signing in…';

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || 'Login failed');
    window.location.href = '/';
  } catch (err) {
    error.textContent = err && err.message ? err.message : 'Login failed';
  } finally {
    button.disabled = false;
    button.textContent = 'Sign In';
  }
  return false;
}

document.addEventListener('DOMContentLoaded', () => {
  redirectIfLoggedIn();
  const form = $('login-form');
  if (form) form.addEventListener('submit', handleLogin);
});
