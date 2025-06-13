import {fetchStatus, showLoader} from '../status/status.js';
import {fetchRuns} from '../runs/runs.js';
import {createRipple} from '../utils/utils.js';

export function initTilt() {
  const cardElement = document.querySelector('.card');
  if (cardElement) {
    VanillaTilt.init(cardElement, {
      max: 8,
      speed: 400,
      glare: true,
      'max-glare': 0.15,
      scale: 1.03
    });
  }
}

export function initBackground() {
  const bgElement = document.getElementById('particles-js-bg');
  if (!bgElement) {
    console.error('Error: #particles-js-bg element not found.');
    return;
  }

  const gradients = [
    'linear-gradient(135deg, #89f7fe, #66a6ff)',
    'linear-gradient(135deg, #66a6ff, #ffb3ba)',
    'linear-gradient(135deg, #ffb3ba, #ffdf7e)',
    'linear-gradient(135deg, #ffdf7e, #b4f8c8)',
    'linear-gradient(135deg, #b4f8c8, #89f7fe)'
  ];

  const selected = gradients[Math.floor(Math.random() * gradients.length)];
  bgElement.style.backgroundImage = selected;
  bgElement.style.animation = 'none';
}

export function initPage() {
  const refreshButton = document.getElementById('refresh');
  if (refreshButton) {
    refreshButton.addEventListener('click', () => {
      showLoader();
      fetchStatus();
    });
    refreshButton.addEventListener('click', createRipple);
  }
  const refreshRunsButton = document.getElementById('refresh-runs');
  if (refreshRunsButton) {
    refreshRunsButton.addEventListener('click', fetchRuns);
    refreshRunsButton.addEventListener('click', createRipple);
  }
  fetchStatus();
  fetchRuns();
  initTilt();
  initBackground();
  initCollapsibleInteractions(); // Initialize collapse interactions
}

export function initCollapsibleInteractions() {
  const recipientCollapse = document.getElementById('recipientManagementCollapse');
  const productCollapse = document.getElementById('productManagementCollapse');

  const recipientButton = document.querySelector('[data-bs-target="#recipientManagementCollapse"]');
  const productButton = document.querySelector('[data-bs-target="#productManagementCollapse"]');

  const setupCollapseIcon = (collapseEl, buttonEl) => {
    if (!collapseEl || !buttonEl) return;
    const icon = buttonEl.querySelector("i[data-lucide]");
    if (!icon) return;

    collapseEl.addEventListener('show.bs.collapse', function () {
      icon.setAttribute('data-lucide', 'chevron-up');
      if (window.lucide) {
        window.lucide.createIcons(); // Re-render icons
      }
    });

    collapseEl.addEventListener('hide.bs.collapse', function () {
      icon.setAttribute('data-lucide', 'chevron-down');
      if (window.lucide) {
        window.lucide.createIcons(); // Re-render icons
      }
    });
  };

  setupCollapseIcon(recipientCollapse, recipientButton);
  setupCollapseIcon(productCollapse, productButton);
}
