import { API_LOGIN, API_USER_LOGIN } from '../config/config.js';
import { showGlobalLoader, hideGlobalLoader } from '../utils/utils.js';

export async function initLogin() {
  showGlobalLoader();
  let loginPopup = document.getElementById('login-popup');
  if (!loginPopup) {
    try {
      const res = await fetch('components/login/login.html');
      const html = await res.text();
      const wrapper = document.createElement('div');
      wrapper.innerHTML = html.trim();
      document.body.prepend(wrapper.firstElementChild);
    } catch (e) {
      console.error('Failed to load login UI:', e);
      return;
    }
    loginPopup = document.getElementById('login-popup');
  }

  const mainAppContent = document.getElementById('main-app-content');

  const adminRoleBtn = document.getElementById('admin-role-btn');
  const userRoleBtn = document.getElementById('user-role-btn');

  const adminSection = document.getElementById('admin-section');
  const userSection = document.getElementById('user-section');

  const adminEmailInput = document.getElementById('admin-email');
  const adminPasswordInput = document.getElementById('admin-password');
  const adminLoginBtn = document.getElementById('admin-login-btn');
  const adminErrorMessage = document.getElementById('admin-error-message'); // Added

  // User section elements
  const userEmailInput = document.getElementById('user-email'); // Reference to the actual input field
  const userEmailWrapper = document.getElementById('user-email-wrapper'); // Wrapper for email input + icon
  const userLoginBtn = document.getElementById('user-login-btn');
  const userErrorMessage = document.getElementById('user-error-message');
  // const userContactAdminText = document.getElementById('user-contact-admin-btn'); // REMOVED - Element deleted from HTML
  const userContactLinks = document.getElementById('user-contact-links');
  const userMailBtn = document.getElementById('user-mail-btn');

  // REMOVE: Old user registration button declarations (userRegYesBtn, userRegNoBtn)
  // const userRegYesBtn = document.getElementById('user-reg-yes');
  // const userRegNoBtn = document.getElementById('user-reg-no');


  function showLoginPopup() {
    hideGlobalLoader();
    if (loginPopup) {
      loginPopup.style.display = 'flex';
    }
    if (adminSection) adminSection.style.display = 'block';
    if (userSection) userSection.style.display = 'none';

    if (adminRoleBtn) adminRoleBtn.classList.add('active');
    if (userRoleBtn) userRoleBtn.classList.remove('active');

    // Initial state for User Section when popup shows (though it's hidden by default)
    // This will also be reset when user tab is clicked
    if (userEmailInput) userEmailInput.value = '';
    if (userEmailWrapper) userEmailWrapper.style.display = 'flex'; // Make email input visible by default in user section
    if (userErrorMessage) userErrorMessage.style.display = 'none';
    // if (userContactAdminText) userContactAdminText.style.display = 'none'; // REMOVED
    if (userContactLinks) userContactLinks.style.display = 'none';

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  }


  if (adminRoleBtn) {
    adminRoleBtn.addEventListener('click', () => {
      if (adminSection) adminSection.style.display = 'block';
      if (userSection) userSection.style.display = 'none';
      adminRoleBtn.classList.add('active');
      if (userRoleBtn) userRoleBtn.classList.remove('active');
      if (adminErrorMessage) adminErrorMessage.style.display = 'none'; // Hide admin error on tab switch
      // Clear admin inputs (optional, but good practice)
      if(adminEmailInput) adminEmailInput.value = '';
      if(adminPasswordInput) adminPasswordInput.value = '';
    });
  }

  if (userRoleBtn) {
    userRoleBtn.addEventListener('click', () => {
      if (adminSection) adminSection.style.display = 'none';
      if (userSection) userSection.style.display = 'block';
      userRoleBtn.classList.add('active');
      if (adminRoleBtn) adminRoleBtn.classList.remove('active');

      // Reset User Section to initial state when tab is clicked
      if (userEmailInput) userEmailInput.value = '';
      if (userEmailWrapper) userEmailWrapper.style.display = 'flex'; // Ensure email input is visible
      if (userErrorMessage) userErrorMessage.style.display = 'none';
      // if (userContactAdminText) userContactAdminText.style.display = 'none'; // REMOVED
      if (userContactLinks) userContactLinks.style.display = 'none';
    });
  }

  if (adminLoginBtn) {
    adminLoginBtn.addEventListener('click', async () => {
      showGlobalLoader();
      const email = adminEmailInput ? adminEmailInput.value.trim() : '';
      const password = adminPasswordInput ? adminPasswordInput.value.trim() : '';

      if (email === '' || password === '') {
        if (adminErrorMessage) {
          adminErrorMessage.textContent = 'Please enter both email and password.';
          adminErrorMessage.style.display = 'block';
        }
        return;
      }

      try {
        const res = await fetch(API_LOGIN, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });

        if (res.ok) {
          const data = await res.json();
          localStorage.setItem('authToken', data.token);
          if (adminErrorMessage) adminErrorMessage.style.display = 'none';
            window.location.href = "components/admin-main/admin.html";
        } else {
          const result = await res.json().catch(() => ({}));
          if (adminErrorMessage) {
            adminErrorMessage.textContent = result.message || 'Invalid credentials.';
            adminErrorMessage.style.display = 'block';
          }
        }
      } catch (e) {
        if (adminErrorMessage) {
          adminErrorMessage.textContent = 'Login failed.';
          adminErrorMessage.style.display = 'block';
        }
      } finally {
        hideGlobalLoader();
      }
    });
  }

  // New User Login Logic
  if (userLoginBtn) {
    userLoginBtn.addEventListener('click', async () => {
      showGlobalLoader();
      const email = userEmailInput ? userEmailInput.value.trim() : '';

      if (email === '') {
        if (userErrorMessage) {
          userErrorMessage.textContent = 'Please enter your email.';
          userErrorMessage.style.display = 'block';
        }
        if (userContactLinks) userContactLinks.style.display = 'none';
        return;
      }

      try {
        const res = await fetch(API_USER_LOGIN, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        });

        if (res.ok) {
          localStorage.setItem('userEmail', email);
          window.location.href = 'components/user-main/user.html';
          return;
        }

        if (userErrorMessage) {
          const result = await res.json().catch(() => ({}));
          userErrorMessage.textContent = result.message || 'Email not registered. Please contact admin to register.';
          userErrorMessage.style.display = 'block';
        }
        if (userContactLinks) {
          userContactLinks.style.display = 'block';
          if (window.lucide && typeof window.lucide.createIcons === 'function') {
            window.lucide.createIcons();
          }
        }
      } catch (e) {
        if (userErrorMessage) {
          userErrorMessage.textContent = 'Login failed.';
          userErrorMessage.style.display = 'block';
        }
      } finally {
        hideGlobalLoader();
      }
    });
  }

  if (userMailBtn) {
    userMailBtn.addEventListener('click', () => {
      const to = 'linktracker03@gmail.com';
      const subject = encodeURIComponent('Register Amul tracker email');
      const typedEmail = userEmailInput ? userEmailInput.value.trim() : '';
      const body = encodeURIComponent(`Hey there!\nPlease register my email : ${typedEmail}`);
      const url = `mailto:${to}?subject=${subject}&body=${body}`;
      window.location.href = url;
    });
  }

  // REMOVE: Old user registration event listeners
  // if (userRegYesBtn) { ... }
  // if (userRegNoBtn) { ... }

  const existingToken = localStorage.getItem('authToken');
  if (existingToken) {
  window.location.href = "components/admin-main/admin.html";
  } else {
    const existingUser = localStorage.getItem('userEmail');
    if (existingUser) {
      window.location.href = 'components/user-main/user.html';
    } else {
      showLoginPopup();
    }
  }
}
