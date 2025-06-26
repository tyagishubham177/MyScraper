import '../status/status.js';
import {initPage} from '../ui/ui.js';
import {initParticles} from '../particles-config/particles-config.js';
import {initIcons} from '../icons/icons.js';
import {initRecipientsUI} from '../recipients-ui/recipients-ui.js';
import {initProductsUI} from '../products-ui/products-ui.js';
import '../subscription/subscriptions-ui.js';

document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('authToken');
  if (!token) {
    window.location.href = '../../index.html';
    return;
  }
  initParticles();
  initPage();
  initIcons();
  initRecipientsUI();
  initProductsUI();

  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('authToken');
        localStorage.removeItem('adminEmail');
        window.location.href = '../../index.html';
      });
  }
});
