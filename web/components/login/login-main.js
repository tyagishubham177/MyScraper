import { initLogin } from './login.js';
import { initParticles } from '../particles-config/particles-config.js';
import { initIcons } from '../icons/icons.js';

document.addEventListener('DOMContentLoaded', () => {
  initLogin();
  initParticles();
  initIcons();
});
