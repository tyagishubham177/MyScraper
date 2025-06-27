export function showToastNotification(message, type = 'info', duration = 4000) {
  let toastContainer = document.querySelector('.toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container';
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement('div');
  toast.className = 'toast-notification';
  toast.classList.add(type);
  toast.textContent = message;
  toastContainer.appendChild(toast);
  void toast.offsetWidth;
  toast.classList.add('show');

  const hideTimeout = setTimeout(() => {
    toast.classList.remove('show');
    toast.addEventListener('transitionend', () => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, { once: true });
  }, duration);

  toast.addEventListener('click', () => {
    clearTimeout(hideTimeout);
    toast.classList.remove('show');
    toast.addEventListener('transitionend', () => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, { once: true });
  }, { once: true });
}

export function getModalFormState() {
  const modalBodyElement = document.getElementById('subscriptionModalBody');
  if (!modalBodyElement) return '';

  const formData = {};
  modalBodyElement.querySelectorAll('.list-group-item').forEach(item => {
    const checkbox = item.querySelector('.subscription-toggle');
    if (!checkbox) return;
    const startInput = item.querySelector('.sub-time-start');
    const endInput = item.querySelector('.sub-time-end');
    const pauseToggle = item.querySelector('.pause-toggle');
    formData[checkbox.dataset.productId] = {
      subscribed: checkbox.checked,
      start: startInput ? startInput.value : '00:00',
      end: endInput ? endInput.value : '23:59',
      paused: pauseToggle ? pauseToggle.checked : false
    };
  });
  return JSON.stringify(formData);
}

export function storeInitialFormState() {
  return getModalFormState();
}

export function updateSaveButtonState(initialState) {
  const saveBtn = document.getElementById('saveAllSubscriptionsBtn');
  if (!saveBtn) return;
  const currentState = getModalFormState();
  if (currentState !== initialState) {
    saveBtn.classList.remove('btn-outline-primary');
    saveBtn.classList.add('btn-primary');
  } else {
    saveBtn.classList.remove('btn-primary');
    saveBtn.classList.add('btn-outline-primary');
  }
}
