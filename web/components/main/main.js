import '../status/status.js';
import {initPage} from '../ui/ui.js';
import {initParticles} from '../particles-config/particles-config.js';
import {initIcons} from '../icons/icons.js';
import { initLogin } from '../login/login.js'; // Import initLogin
import {initRecipientsUI} from '../recipients-ui/recipients-ui.js';
import {initProductsUI} from '../products-ui/products-ui.js';
import '../subscription/subscriptions-ui.js'; // Ensures subscriptions UI is initialized

document.addEventListener('DOMContentLoaded', () => {
  initLogin(); // Initialize and show the login popup
  initParticles();
  initPage();
  initIcons();
  initRecipientsUI();
  initProductsUI();
  // initSubscriptionsUI(); // This is now self-initializing via the import above
});
