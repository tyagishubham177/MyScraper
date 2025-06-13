import {API_ENABLE, API_DISABLE, API_STATUS, API_DISPATCH} from './config.js';
import {createRipple} from './utils.js';
import {fetchRuns} from './runs.js';

const loader = document.getElementById('loader');
const statusSpan = document.getElementById('status');
// const enableButton = document.getElementById('enable');
// const disableButton = document.getElementById('disable');
// const dispatchButton = document.getElementById('dispatch');

export const showLoader = () => {
  loader.style.display = 'inline-block';
  statusSpan.classList.add('status-loading-pulse');
};

export const hideLoader = () => {
  loader.style.display = 'none';
  statusSpan.classList.remove('status-loading-pulse');
};

export async function call(path) {
  showLoader();
  try {
    await fetch(path, {method: 'POST'});
  } catch (e) {
    console.error('Action error:', e);
  }
  await fetchStatus();
}

/*
async function runWorkflow() {
  showLoader();
  try {
    let state = null;
    const res = await fetch(API_STATUS);
    if (res.ok) {
      const data = await res.json();
      state = data.state;
    }
    if (state && state.toLowerCase() === 'disabled') {
      await fetch(API_ENABLE, {method: 'POST'});
    }
    await fetch(API_DISPATCH, {method: 'POST'});
  } catch (e) {
    console.error('Action error:', e);
  }
  await fetchStatus();
  setTimeout(fetchRuns, 5000);
}

enableButton.addEventListener('click', () => call(API_ENABLE));
disableButton.addEventListener('click', () => call(API_DISABLE));
dispatchButton.addEventListener('click', runWorkflow);
[enableButton, disableButton, dispatchButton].forEach(btn => btn && btn.addEventListener('click', createRipple));
*/

export async function fetchStatus() {
  statusSpan.textContent = 'Loading…';
  statusSpan.className = 'fw-bold badge bg-info-subtle text-info-emphasis rounded-pill status-loading-pulse';
  // enableButton.classList.remove('glow-success', 'glow-danger');
  // disableButton.classList.remove('glow-success', 'glow-danger');
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
      // enableButton.classList.add('glow-success');
    } else if (data.state && data.state.toLowerCase() === 'disabled') {
      statusSpan.classList.add('badge', 'bg-danger-subtle', 'text-danger-emphasis', 'rounded-pill');
      // disableButton.classList.add('glow-danger');
    } else {
      statusSpan.classList.add('badge', 'bg-secondary-subtle', 'text-secondary-emphasis', 'rounded-pill');
    }
  } catch (e) {
    statusSpan.textContent = 'Error';
    statusSpan.className = 'fw-bold badge bg-warning-subtle text-warning-emphasis rounded-pill';
  }
  hideLoader();
}
