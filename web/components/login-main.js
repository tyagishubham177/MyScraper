import { initLogin } from './login.js';
import { initParticles } from './particles-config.js';
import { initIcons } from './icons.js';

document.addEventListener('DOMContentLoaded', () => {
  initLogin();
  initParticles();
  initIcons();
});
