import { initParticles } from "../particles-config/particles-config.js";
import { initIcons } from "../icons/icons.js";
import { initBackground } from "../ui/ui.js";
import { initUserSubscriptionsUI } from "../user-subscriptions/user-subscriptions.js";
import { showGlobalLoader, hideGlobalLoader, escapeHTML, fetchAPI, normalizeEmail } from "../utils/utils.js";
import { showToastNotification } from "../subscription/subscription-helpers.js";

document.addEventListener("DOMContentLoaded", async () => {
  showGlobalLoader();

  const storedEmail = localStorage.getItem('userEmail');
  const displayEmail = localStorage.getItem('userEmailDisplay') || storedEmail;
  const email = normalizeEmail(storedEmail);
  if (!email) {
    window.location.href = '../../index.html';
    return;
  }
  if (storedEmail !== email) {
    localStorage.setItem('userEmail', email);
  }
  if (displayEmail && displayEmail !== storedEmail) {
    localStorage.setItem('userEmailDisplay', displayEmail);
  }

  const legacySuffix = displayEmail && displayEmail !== email ? displayEmail : null;
  const migrateKey = (prefix) => {
    if (!legacySuffix) return null;
    const legacyValue = localStorage.getItem(`${prefix}_${legacySuffix}`);
    const normalizedKey = `${prefix}_${email}`;
    if (legacyValue && !localStorage.getItem(normalizedKey)) {
      localStorage.setItem(normalizedKey, legacyValue);
      localStorage.removeItem(`${prefix}_${legacySuffix}`);
    }
    return legacyValue;
  };

  migrateKey('recipientId');
  migrateKey('pincode');
  let legacyUsername = migrateKey('username');

  const welcomeEl = document.getElementById('welcome-msg');
  function getGreeting() {
    const h = new Date().getHours();
    if (h < 12) return 'Good Morning';
    if (h < 18) return 'Good Afternoon';
    return 'Good Evening';
  }

  function updateWelcome() {
    const username = localStorage.getItem(`username_${email}`) || legacyUsername || '';
    const safeName = escapeHTML(username);
    const safeEmail = escapeHTML(displayEmail || email);

    welcomeEl.innerHTML = '';

    const textWrap = document.createElement('span');
    textWrap.className = 'welcome-text';

    const greetingSpan = document.createElement('span');
    greetingSpan.className = 'welcome-greeting';
    greetingSpan.textContent = username
      ? `Hi ${safeName}! ${getGreeting()}`
      : `Hi! ${getGreeting()}`;

    textWrap.appendChild(greetingSpan);
    if (!username) {
      const emailSpan = document.createElement('span');
      emailSpan.className = 'welcome-email';
      emailSpan.textContent = safeEmail;
      textWrap.appendChild(emailSpan);
    }
    welcomeEl.appendChild(textWrap);

    const iconEl = document.createElement('i');
    iconEl.id = 'edit-username';
    iconEl.dataset.lucide = 'edit';
    iconEl.className = 'ms-2';
    iconEl.role = 'button';
    iconEl.setAttribute('aria-label', 'Edit display name');
    iconEl.style.cursor = 'pointer';
    welcomeEl.appendChild(iconEl);

    if (window.lucide) window.lucide.createIcons();
  }

  updateWelcome();

  const settingsFab = document.querySelector('.fab');
  const settingsPaneEl = document.getElementById('settingsPane');
  if (settingsFab && settingsPaneEl) {
    settingsPaneEl.addEventListener('show.bs.offcanvas', () => {
      settingsFab.classList.add('is-hidden');
    });
    settingsPaneEl.addEventListener('hidden.bs.offcanvas', () => {
      settingsFab.classList.remove('is-hidden');
    });
  }

  setTimeout(() => {
    welcomeEl.classList.remove('initial');
    welcomeEl.classList.add('shrunk');
  }, 2500);

  welcomeEl.addEventListener('click', (e) => {
    if (e.target.closest('#edit-username')) {
      const input = document.getElementById('username-input');
      input.value = localStorage.getItem(`username_${email}`) || legacyUsername || '';
      const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('usernameModal'));
      modal.show();
    }
  });

  document.getElementById('save-username-btn').addEventListener('click', () => {
    const name = document.getElementById('username-input').value.trim();
    if (name) {
      localStorage.setItem(`username_${email}`, name);
      if (legacySuffix) {
        localStorage.removeItem(`username_${legacySuffix}`);
      }
      legacyUsername = null;
    } else {
      localStorage.removeItem(`username_${email}`);
      if (legacySuffix) {
        localStorage.removeItem(`username_${legacySuffix}`);
      }
      legacyUsername = null;
    }
    const modal = bootstrap.Modal.getInstance(document.getElementById('usernameModal'));
    if (modal) modal.hide();
    updateWelcome();
  });

  document.getElementById('change-username-btn').addEventListener('click', () => {
    const input = document.getElementById('username-input');
    input.value = localStorage.getItem(`username_${email}`) || legacyUsername || '';
    const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('usernameModal'));
    modal.show();
  });

  const switchAdminBtn = document.getElementById('switch-to-admin-btn');
  const fromAdmin = localStorage.getItem('switchedFromAdmin') === 'true';
  if (switchAdminBtn) {
    if (!fromAdmin) {
      switchAdminBtn.style.display = 'none';
    } else {
      switchAdminBtn.addEventListener('click', () => {
        localStorage.removeItem('switchedFromAdmin');
        window.location.href = '../admin-main/admin.html';
      });
    }
  }

  document.getElementById('logout-btn').addEventListener('click', () => {
    localStorage.removeItem('userEmail');
    localStorage.removeItem('userEmailDisplay');
    localStorage.removeItem('authToken');
    localStorage.removeItem('adminEmail');
    localStorage.removeItem('adminEmailDisplay');
    localStorage.removeItem('switchedFromAdmin');
    window.location.href = '../../index.html';
  });

  const backBtn = document.getElementById('back-to-admin-btn');
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      localStorage.removeItem('userEmail');
      localStorage.removeItem('userEmailDisplay');
      window.location.href = '../admin-main/admin.html';
    });
  }

  initParticles();
  initIcons();
  initBackground();
  
  const container = document.getElementById('user-subscriptions-container');
  if (container) {
    try {
      const res = await fetch('../user-subscriptions/user-subscriptions.html');
      container.innerHTML = await res.text();
    } catch (e) {
      console.error('Failed to load subscription UI', e);
    }
    await initUserSubscriptionsUI();
  }

  const pincodeInput = document.getElementById('pincode-input');
  const savePinBtn = document.getElementById('save-pincode-btn');
  if (pincodeInput) {
    const storedPin = localStorage.getItem(`pincode_${email}`) || (legacySuffix ? localStorage.getItem(`pincode_${legacySuffix}`) : null) || '201305';
    if (legacySuffix && localStorage.getItem(`pincode_${legacySuffix}`) && !localStorage.getItem(`pincode_${email}`)) {
      localStorage.setItem(`pincode_${email}`, localStorage.getItem(`pincode_${legacySuffix}`));
    }
    pincodeInput.value = storedPin;
  }
  if (savePinBtn && pincodeInput) {
    savePinBtn.addEventListener('click', async () => {
      const pin = (pincodeInput.value || '').trim();
      if (!/^\d{6}$/.test(pin)) {
        alert('Enter valid pincode');
        return;
      }
      const rid = localStorage.getItem(`recipientId_${email}`) || (legacySuffix ? localStorage.getItem(`recipientId_${legacySuffix}`) : null);
      if (!rid) return;
      showGlobalLoader();
      try {
        await fetchAPI(`/api/recipients?id=${rid}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pincode: pin })
        });
        localStorage.setItem(`pincode_${email}`, pin);
        if (legacySuffix) {
          localStorage.removeItem(`pincode_${legacySuffix}`);
        }
        const offcanvasEl = document.getElementById('settingsPane');
        const off = offcanvasEl ? bootstrap.Offcanvas.getOrCreateInstance(offcanvasEl) : null;
        if (off) off.hide();
        showToastNotification('Pincode saved successfully.', 'success');
      } catch (e) {
        console.error('Failed to save pincode', e);
        showToastNotification('Failed to save pincode.', 'error');
      } finally {
        hideGlobalLoader();
      }
    });
  }
  
  hideGlobalLoader();
  
  const gmailLink = document.getElementById('feedbackGmail');
  const to = 'linktracker03@gmail.com';
  const subject = encodeURIComponent('Product Request / Feedback');
  const body = encodeURIComponent(`Hey there! I would like to request a new product or send feedback. My email: ${displayEmail || email}`);
  if (gmailLink) {
    gmailLink.addEventListener('click', (e) => {
      e.preventDefault();
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
});
