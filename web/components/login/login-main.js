import { initLogin } from './login.js';
import { initParticles } from '../particles-config/particles-config.js';
import { initIcons } from '../icons/icons.js';
import { initBackground } from '../ui/ui.js';

document.addEventListener('DOMContentLoaded', () => {
  initLogin();
  initParticles();
  initBackground();
  initIcons();
});
