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
  const userRedditLink = document.getElementById('user-reddit-link');

  // REMOVE: Old user registration button declarations (userRegYesBtn, userRegNoBtn)
  // const userRegYesBtn = document.getElementById('user-reg-yes');
  // const userRegNoBtn = document.getElementById('user-reg-no');

  let adminCountdownTimer = null;
  let userCountdownTimer = null;

  function showError(elem, msg) {
    if (elem) {
      elem.textContent = msg;
      elem.style.display = 'block';
    }
  }

  function handleAdminError(result) {
    if (result.wait) {
      const lockUntil = Date.now() + result.wait * 1000;
      localStorage.setItem('adminLockUntil', lockUntil);
      if (adminCountdownTimer) clearInterval(adminCountdownTimer);
      adminCountdownTimer = startCountdown(
        adminLoginBtn,
        lockUntil,
        adminErrorMessage,
        'adminLockUntil'
      );
    } else if (result.attempt) {
      let msg = `Unsuccessful attempt ${result.attempt}/3`;
      if (result.attempt === 2) msg += ' - last attempt';
      showError(adminErrorMessage, msg);
    } else {
      showError(adminErrorMessage, result.message || 'Invalid credentials.');
    }
  }

  function handleUserError(result) {
    if (result.wait) {
      const lockUntil = Date.now() + result.wait * 1000;
      localStorage.setItem('userLockUntil', lockUntil);
      if (userCountdownTimer) clearInterval(userCountdownTimer);
      userCountdownTimer = startCountdown(
        userLoginBtn,
        lockUntil,
        userErrorMessage,
        'userLockUntil',
        userContactLinks
      );
    } else {
      let msg;
      if (result.attempt) {
        msg = `Email unregistered or incorrect attempt (${result.attempt}/3)`;
        if (result.attempt === 2) msg += ' - last attempt';
        msg += '. Please contact admin to register via options below';
      } else {
        msg = result.message || 'Email not registered. Please contact admin to register via options below';
      }
      showError(userErrorMessage, msg);
      if (userContactLinks) {
        userContactLinks.style.display = 'block';
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
          window.lucide.createIcons();
        }
      }
    }
  }

  function clearCountdown(timerVar, storageKey, messageElem, contactLinks) {
    if (timerVar) {
      clearInterval(timerVar);
    }
    if (storageKey) localStorage.removeItem(storageKey);
    if (messageElem) messageElem.style.display = 'none';
    if (contactLinks) contactLinks.style.display = 'none';
    return null;
  }

  function startCountdown(button, lockUntil, messageElem, storageKey, contactLinks) {
    if (!button) return null;
    button.disabled = true;
    function update() {
      const remaining = Math.ceil((lockUntil - Date.now()) / 1000);
      if (remaining > 0) {
        if (messageElem) {
          messageElem.textContent = `Too many attempts. Try again in ${remaining}s`;
          messageElem.style.display = 'block';
        }
        if (contactLinks) {
          contactLinks.style.display = 'block';
          if (window.lucide && typeof window.lucide.createIcons === 'function') {
            window.lucide.createIcons();
          }
        }
      } else {
        clearInterval(timer);
        button.disabled = false;
        localStorage.removeItem(storageKey);
        if (messageElem) messageElem.style.display = 'none';
        if (contactLinks) contactLinks.style.display = 'none';
      }
    }
    update();
    const timer = setInterval(update, 1000);
    return timer;
  }

  function checkStoredLock(button, messageElem, storageKey, contactLinks) {
    const lockUntil = parseInt(localStorage.getItem(storageKey), 10);
    if (lockUntil && lockUntil > Date.now()) {
      return startCountdown(button, lockUntil, messageElem, storageKey, contactLinks);
    }
    localStorage.removeItem(storageKey);
    return null;
  }


  function showLoginPopup() {
    hideGlobalLoader();
    if (loginPopup) {
      loginPopup.style.display = 'flex';
    }
    if (adminSection) adminSection.style.display = 'none';
    if (userSection) userSection.style.display = 'block';

    if (userRoleBtn) userRoleBtn.classList.add('active');
    if (adminRoleBtn) adminRoleBtn.classList.remove('active');

    // Initial state for User Section when popup shows (though it's hidden by default)
    // This will also be reset when user tab is clicked
    if (userEmailInput) userEmailInput.value = '';
    if (userEmailWrapper) userEmailWrapper.style.display = 'flex'; // Make email input visible by default in user section
    if (userErrorMessage) userErrorMessage.style.display = 'none';
    // if (userContactAdminText) userContactAdminText.style.display = 'none'; // REMOVED
    if (userContactLinks) userContactLinks.style.display = 'none';

    adminCountdownTimer = clearCountdown(adminCountdownTimer, null, adminErrorMessage);
    adminCountdownTimer = checkStoredLock(adminLoginBtn, adminErrorMessage, 'adminLockUntil');
    userCountdownTimer = clearCountdown(userCountdownTimer, null, userErrorMessage, userContactLinks);
    userCountdownTimer = checkStoredLock(userLoginBtn, userErrorMessage, 'userLockUntil', userContactLinks);

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
      adminCountdownTimer = clearCountdown(adminCountdownTimer, null, adminErrorMessage);
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
      userCountdownTimer = clearCountdown(userCountdownTimer, null, userErrorMessage, userContactLinks);
      userCountdownTimer = checkStoredLock(userLoginBtn, userErrorMessage, 'userLockUntil', userContactLinks);
    });
  }

  async function handleAdminLogin() {
    showGlobalLoader();
    const email = adminEmailInput ? adminEmailInput.value.trim() : '';
    const password = adminPasswordInput ? adminPasswordInput.value.trim() : '';
    if (!email || !password) {
      showError(adminErrorMessage, 'Please enter both email and password.');
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
        adminCountdownTimer = clearCountdown(adminCountdownTimer, 'adminLockUntil', adminErrorMessage);
        window.location.href = "components/admin-main/admin.html";
      } else {
        const result = await res.json().catch(() => ({}));
        handleAdminError(result);
      }
    } catch (e) {
      showError(adminErrorMessage, 'Login failed.');
    } finally {
      hideGlobalLoader();
    }
  }

  if (adminLoginBtn) {
    adminLoginBtn.addEventListener('click', handleAdminLogin);
  }

  // New User Login Logic
  async function handleUserLogin() {
    showGlobalLoader();
    const email = userEmailInput ? userEmailInput.value.trim() : '';
    if (email === '') {
      showError(userErrorMessage, 'Please enter your email.');
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
        userCountdownTimer = clearCountdown(userCountdownTimer, 'userLockUntil', userErrorMessage, userContactLinks);
        localStorage.setItem('userEmail', email);
        window.location.href = 'components/user-main/user.html';
        return;
      }
      const result = await res.json().catch(() => ({}));
      handleUserError(result);
    } catch (e) {
      showError(userErrorMessage, 'Login failed.');
    } finally {
      hideGlobalLoader();
    }
  }

  if (userLoginBtn) {
    userLoginBtn.addEventListener('click', handleUserLogin);
  }

  if (userMailBtn) {
    userMailBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const to = 'linktracker03@gmail.com';
      const subject = encodeURIComponent('Register Amul tracker email');
      const typedEmail = userEmailInput ? userEmailInput.value.trim() : '';
      const body = encodeURIComponent(`Hey there!\nPlease register my email : ${typedEmail}`);
      const isMobile = /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
      let url;
      if (isMobile) {
        url = `mailto:${to}?subject=${subject}&body=${body}`;
        window.location.href = url;
      } else {
        url = `https://mail.google.com/mail/?view=cm&fs=1&to=${to}&su=${subject}&body=${body}`;
        window.open(url, '_blank');
      }
    });
  }

  if (userRedditLink) {
    userRedditLink.addEventListener('click', (e) => {
      e.preventDefault();
      const baseUrl = 'https://www.reddit.com/message/compose/';
      const to = 'ShooBum-T';
      const subject = encodeURIComponent('User Registration Request');
      const typedEmail = userEmailInput ? userEmailInput.value.trim() : '';
      const message = encodeURIComponent(`Please register my email : ${typedEmail}`);
      const url = `${baseUrl}?to=${to}&subject=${subject}&message=${message}`;
      window.open(url, '_blank');
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
