import './status.js';
import {initPage} from './ui.js';
import {initParticles} from './particles-config.js';
import {initIcons} from './icons.js';
import {initRecipientsUI} from './recipients-ui.js';
import {initProductsUI} from './products-ui.js';
import './subscriptions-ui.js';

document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('authToken');
  if (!token) {
    window.location.href = 'index.html';
    return;
  }
  initParticles();
  initPage();
  initIcons();
  initRecipientsUI();
  initProductsUI();
});
