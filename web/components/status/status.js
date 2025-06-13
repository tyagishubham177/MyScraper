import {API_STATUS} from '../config/config.js';

const loader = document.getElementById('loader');
const statusSpan = document.getElementById('status');

export const showLoader = () => {
  loader.style.display = 'inline-block';
  statusSpan.classList.add('status-loading-pulse');
};

export const hideLoader = () => {
  loader.style.display = 'none';
  statusSpan.classList.remove('status-loading-pulse');
};


export async function fetchStatus() {
  statusSpan.textContent = 'Loading…';
  statusSpan.className = 'fw-bold badge bg-info-subtle text-info-emphasis rounded-pill status-loading-pulse';
  try {
    const res = await fetch(API_STATUS);
    if (!res.ok) {
      statusSpan.textContent = 'Error';
      statusSpan.className = 'fw-bold badge bg-warning-subtle text-warning-emphasis rounded-pill';
      hideLoader();
      return;
    }
    const data = await res.json();
    statusSpan.textContent = data.state;
    statusSpan.className = 'fw-bold';
    statusSpan.classList.remove('status-loading-pulse');
    if (data.state && data.state.toLowerCase() === 'enabled') {
    statusSpan.classList.add('badge', 'bg-success-subtle', 'text-success-emphasis', 'rounded-pill');
    } else if (data.state && data.state.toLowerCase() === 'disabled') {
    statusSpan.classList.add('badge', 'bg-danger-subtle', 'text-danger-emphasis', 'rounded-pill');
    } else {
      statusSpan.classList.add('badge', 'bg-secondary-subtle', 'text-secondary-emphasis', 'rounded-pill');
    }
  } catch (e) {
    statusSpan.textContent = 'Error';
    statusSpan.className = 'fw-bold badge bg-warning-subtle text-warning-emphasis rounded-pill';
  }
  hideLoader();
}
