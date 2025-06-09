import './status.js';
import {initPage} from './ui.js';
import {initParticles} from './particles-config.js';
import {initIcons} from './icons.js';
import {initRecipientsUI} from './recipients-ui.js';
import {initProductsUI} from './products-ui.js';
import {initSubscriptionsUI} from './subscriptions-ui.js';

document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  initPage();
  initIcons();
  initRecipientsUI();
  initProductsUI();
  initSubscriptionsUI();
});
