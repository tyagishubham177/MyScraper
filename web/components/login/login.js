import { API_LOGIN, API_USER_LOGIN } from '../config/config.js';
import { showGlobalLoader, hideGlobalLoader, normalizeEmail } from '../utils/utils.js';

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

  const loginIcon =
    loginPopup && typeof loginPopup.querySelector === 'function'
      ? loginPopup.querySelector('.login-icon i')
      : null;

  const adminSection = document.getElementById('admin-section');
  const userSection = document.getElementById('user-section');

  const loginContainer =
    loginPopup && typeof loginPopup.querySelector === 'function'
      ? loginPopup.querySelector('.login-container')
      : null;

  const adminEmailInput = document.getElementById('admin-email');
  const adminPasswordInput = document.getElementById('admin-password');
  const adminPasswordToggle = document.getElementById('admin-password-toggle');
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

  function adjustContainerHeight() {
    if (!loginContainer || !adminSection || !userSection) return;
    const adminDisplay = adminSection.style.display;
    const userDisplay = userSection.style.display;
    adminSection.style.display = 'block';
    userSection.style.display = 'block';
    const maxHeight = Math.max(adminSection.offsetHeight, userSection.offsetHeight);
    loginContainer.style.minHeight = maxHeight + 'px';
    adminSection.style.display = adminDisplay;
    userSection.style.display = userDisplay;
  }

  adjustContainerHeight();

  function animateSection(section) {
    if (section) {
      section.classList.remove('fade-slide-in');
      void section.offsetWidth;
      section.classList.add('fade-slide-in');
    }
  }

  if (adminPasswordToggle && adminPasswordInput) {
    adminPasswordToggle.addEventListener('click', () => {
      const visible = adminPasswordInput.getAttribute('type') === 'text';
      adminPasswordInput.setAttribute('type', visible ? 'password' : 'text');
      adminPasswordToggle.setAttribute('data-lucide', visible ? 'eye' : 'eye-off');
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
    });
  }

  function showError(elem, msg) {
    if (elem) {
      elem.textContent = msg;
      elem.classList.remove('hidden');
      elem.style.display = 'block';
    }
  }

  function hideElem(elem) {
    if (elem) {
      elem.classList.add('hidden');
      elem.style.display = 'none';
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
        userContactLinks.classList.remove('hidden');
        userContactLinks.style.display = 'flex';
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
    if (messageElem) hideElem(messageElem);
    if (contactLinks) hideElem(contactLinks);
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
          messageElem.classList.remove('hidden');
          messageElem.style.display = 'block';
        }
        if (contactLinks) {
          contactLinks.classList.remove('hidden');
          contactLinks.style.display = 'flex';
          if (window.lucide && typeof window.lucide.createIcons === 'function') {
            window.lucide.createIcons();
          }
        }
      } else {
        clearInterval(timer);
        button.disabled = false;
        localStorage.removeItem(storageKey);
        if (messageElem) hideElem(messageElem);
        if (contactLinks) hideElem(contactLinks);
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
    if (adminSection) {
      adminSection.classList.add('hidden');
      adminSection.style.display = 'none';
    }
    if (userSection) {
      userSection.classList.remove('hidden');
      userSection.style.display = 'block';
    }

    if (loginIcon) {
      loginIcon.setAttribute('data-lucide', 'user');
    }

    if (userRoleBtn) userRoleBtn.classList.add('active');
    if (adminRoleBtn) adminRoleBtn.classList.remove('active');

    // Initial state for User Section when popup shows (though it's hidden by default)
    // This will also be reset when user tab is clicked
    if (userEmailInput) userEmailInput.value = '';
    if (userEmailWrapper) userEmailWrapper.style.display = 'flex'; // Make email input visible by default in user section
    if (userErrorMessage) hideElem(userErrorMessage);
    if (userContactLinks) hideElem(userContactLinks);

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
      if (adminSection) {
        adminSection.classList.remove('hidden');
        adminSection.style.display = 'block';
        animateSection(adminSection);
      }
      if (userSection) {
        userSection.classList.add('hidden');
        userSection.style.display = 'none';
      }
      if (loginIcon) {
        loginIcon.setAttribute('data-lucide', 'shield');
      }
      adminRoleBtn.classList.add('active');
      if (userRoleBtn) userRoleBtn.classList.remove('active');
      if (adminErrorMessage) hideElem(adminErrorMessage); // Hide admin error on tab switch
      // Clear admin inputs (optional, but good practice)
      if(adminEmailInput) adminEmailInput.value = '';
      if(adminPasswordInput) adminPasswordInput.value = '';
      adminCountdownTimer = clearCountdown(adminCountdownTimer, null, adminErrorMessage);
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
    });
  }

  if (userRoleBtn) {
    userRoleBtn.addEventListener('click', () => {
      if (adminSection) {
        adminSection.classList.add('hidden');
        adminSection.style.display = 'none';
      }
      if (userSection) {
        userSection.classList.remove('hidden');
        userSection.style.display = 'block';
        animateSection(userSection);
      }
      if (loginIcon) {
        loginIcon.setAttribute('data-lucide', 'user');
      }
      userRoleBtn.classList.add('active');
      if (adminRoleBtn) adminRoleBtn.classList.remove('active');

      // Reset User Section to initial state when tab is clicked
      if (userEmailInput) userEmailInput.value = '';
      if (userEmailWrapper) userEmailWrapper.style.display = 'flex'; // Ensure email input is visible
      if (userErrorMessage) hideElem(userErrorMessage);
      // if (userContactAdminText) userContactAdminText.style.display = 'none'; // REMOVED
      if (userContactLinks) hideElem(userContactLinks);
      userCountdownTimer = clearCountdown(userCountdownTimer, null, userErrorMessage, userContactLinks);
      userCountdownTimer = checkStoredLock(userLoginBtn, userErrorMessage, 'userLockUntil', userContactLinks);
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
    });
  }

  async function handleAdminLogin() {
    const typedEmail = adminEmailInput ? adminEmailInput.value.trim() : '';
    const email = normalizeEmail(typedEmail);
    const password = adminPasswordInput ? adminPasswordInput.value.trim() : '';
    if (!typedEmail || !password) {
      showError(adminErrorMessage, 'Please enter both email and password.');
      return;
    }
    showGlobalLoader();
    try {
      const res = await fetch(API_LOGIN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('adminEmail', email);
        if (typedEmail && typedEmail !== email) {
          localStorage.setItem('adminEmailDisplay', typedEmail);
        } else {
          localStorage.removeItem('adminEmailDisplay');
        }
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
    const typedEmail = userEmailInput ? userEmailInput.value.trim() : '';
    const email = normalizeEmail(typedEmail);
    if (typedEmail === '') {
      showError(userErrorMessage, 'Please enter your email.');
      if (userContactLinks) hideElem(userContactLinks);
      return;
    }
    showGlobalLoader();
    try {
      const res = await fetch(API_USER_LOGIN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      if (res.ok) {
        userCountdownTimer = clearCountdown(userCountdownTimer, 'userLockUntil', userErrorMessage, userContactLinks);
        localStorage.setItem('userEmail', email);
        if (typedEmail && typedEmail !== email) {
          localStorage.setItem('userEmailDisplay', typedEmail);
        } else {
          localStorage.removeItem('userEmailDisplay');
        }
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
