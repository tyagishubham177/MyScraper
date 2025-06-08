import './status.js';
import {initPage} from './ui.js';
import {initParticles} from './particles-config.js';
import {initIcons} from './icons.js';

document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  initPage();
  initIcons();
});
