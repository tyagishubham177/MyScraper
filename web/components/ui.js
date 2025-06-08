import {fetchStatus} from './status.js';
import {fetchRuns} from './runs.js';

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
  fetchStatus();
  fetchRuns();
  initTilt();
  initBackground();
}
