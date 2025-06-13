import './status.js';
import {initPage} from './ui.js';
import {initParticles} from './particles-config.js';
import {initIcons} from './icons.js';
import { initLogin } from './login.js'; // Import initLogin
import {initRecipientsUI} from './recipients-ui.js';
import {initProductsUI} from './products-ui.js';
import './subscriptions-ui.js'; // Ensures subscriptions UI is initialized

document.addEventListener('DOMContentLoaded', () => {
  initLogin(); // Initialize and show the login popup
  initParticles();
  initPage();
  initIcons();
  initRecipientsUI();
  initProductsUI();
  // initSubscriptionsUI(); // This is now self-initializing via the import above
});
