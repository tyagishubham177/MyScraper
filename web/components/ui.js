import {fetchStatus, showLoader} from './status.js';
import {fetchRuns} from './runs.js';
import {createRipple} from './utils.js';

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
  try {
    const storedBackground = localStorage.getItem('fixedBackground');
    if (storedBackground) {
      bgElement.style.background = storedBackground;
      bgElement.style.animation = 'none';
    } else {
      setTimeout(() => {
        const computedStyle = window.getComputedStyle(bgElement).getPropertyValue('background-image');
        if (computedStyle && computedStyle !== 'none') {
          localStorage.setItem('fixedBackground', computedStyle);
          bgElement.style.background = computedStyle;
          bgElement.style.animation = 'none';
        }
      }, 1000);
    }
  } catch (e) {
    console.error('Error accessing localStorage or applying background:', e);
  }
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
