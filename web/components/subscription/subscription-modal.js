import {
  showToastNotification,
  storeInitialFormState as storeInitialFormStateHelper,
  updateSaveButtonState as updateSaveButtonStateHelper
} from './subscription-helpers.js';
import { fetchAPI } from '../utils/utils.js';

let currentModalRecipientId = null;
let initialSubscriptionDataForModal = '';
let initialSubscribedProductIds = new Set();

function toggleSaveButton(disabled, text) {
  const btn = document.getElementById('saveAllSubscriptionsBtn');
  if (!btn) return;
  btn.disabled = disabled;
  btn.innerHTML = disabled ? '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...' : text;
}

async function updateSubscription(item, recipientId, results) {
  const mainCheckbox = item.querySelector('.subscription-toggle');
  if (!mainCheckbox) return;
  const productId = mainCheckbox.dataset.productId;
  const isSubscribed = mainCheckbox.checked;
  const startInput = item.querySelector('.sub-time-start');
  const endInput = item.querySelector('.sub-time-end');
  const pauseToggle = item.querySelector('.pause-toggle');
  const startVal = startInput ? startInput.value : '00:00';
  const endVal = endInput ? endInput.value : '23:59';
  const pausedVal = pauseToggle ? pauseToggle.checked : false;
  try {
    if (isSubscribed) {
      const payload = { recipient_id: recipientId, product_id: productId, start_time: startVal, end_time: endVal, paused: pausedVal };
      const data = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      results.push({ productId, success: true, data });
    } else if (initialSubscribedProductIds.has(productId)) {
      const payload = { recipient_id: recipientId, product_id: productId };
      const data = await fetchAPI('/api/subscriptions', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      results.push({ productId, success: true, data, operation: 'deleted' });
    }
  } catch (error) {
    showToastNotification(`Failed to update product ${productId}: ${error.message}`, 'error');
    results.push({ productId, success: false, error });
  }
}

function summarizeResults(results) {
  let successCount = 0;
  let errorCount = 0;
  const errorMessages = [];
  results.forEach(result => {
    if (result.success) {
      successCount++;
    } else {
      errorCount++;
      const msg = result.error && result.error.message ? result.error.message : 'Unknown error';
      errorMessages.push(`Product ID ${result.productId}: ${msg}`);
    }
  });
  let feedbackMessage = '';
  if (successCount > 0) feedbackMessage += `${successCount} subscription operation(s) processed successfully. `;
  if (errorCount > 0) feedbackMessage += `Encountered ${errorCount} error(s): ${errorMessages.join('; ')}.`;
  let toastType = 'info';
  if (errorCount > 0 && successCount > 0) toastType = 'warning';
  else if (errorCount > 0 && successCount === 0) toastType = 'error';
  else if (successCount > 0 && errorCount === 0) toastType = 'success';
  if (feedbackMessage.trim()) showToastNotification(feedbackMessage.trim(), toastType);
}

function renderSubscriptionProductsInModal(allProducts, recipientSubscriptions, recipientId, modalBodyElement) {
  modalBodyElement.innerHTML = '';
  if (!allProducts || allProducts.length === 0) {
    modalBodyElement.innerHTML = '<div class="list-group-item">No products available.</div>';
    return;
  }

  const subscribedProductIds = new Set(recipientSubscriptions.map(sub => sub.product_id));
  const timeMap = {};
  recipientSubscriptions.forEach(sub => {
    timeMap[sub.product_id] = {
      start: sub.start_time || '00:00',
      end: sub.end_time || '23:59'
    };
  });
  const sortedProducts = [...allProducts].sort((a, b) => {
    const aSub = subscribedProductIds.has(a.id);
    const bSub = subscribedProductIds.has(b.id);
    if (aSub && !bSub) return -1;
    if (!aSub && bSub) return 1;
    return a.name.localeCompare(b.name);
  });

  sortedProducts.forEach(product => {
    const listItem = document.createElement('div');
    listItem.className = 'list-group-item subscription-item mb-3 p-3 border rounded';

    const mainToggleDiv = document.createElement('div');
    mainToggleDiv.className = 'form-check mb-0';
    const mainCheckbox = document.createElement('input');
    mainCheckbox.type = 'checkbox';
    mainCheckbox.id = `sub-check-${recipientId}-${product.id}`;
    mainCheckbox.className = 'form-check-input subscription-toggle';
    mainCheckbox.setAttribute('data-product-id', product.id);
    mainCheckbox.checked = subscribedProductIds.has(product.id);

    const mainLabel = document.createElement('label');
    mainLabel.className = 'form-check-label ms-2 fw-bold';
    mainLabel.setAttribute('for', mainCheckbox.id);
    mainLabel.textContent = product.name;

    mainToggleDiv.appendChild(mainCheckbox);
    mainToggleDiv.appendChild(mainLabel);
    listItem.appendChild(mainToggleDiv);

    const timeDiv = document.createElement('div');
    timeDiv.className = 'time-controls d-flex align-items-center ms-4 flex-nowrap';
    const startInput = document.createElement('input');
    startInput.type = 'time';
    startInput.className = 'form-control form-control-sm sub-time-start me-2';
    startInput.value = (timeMap[product.id]?.start) || '00:00';
    startInput.dataset.productId = product.id;
    const endInput = document.createElement('input');
    endInput.type = 'time';
    endInput.className = 'form-control form-control-sm sub-time-end me-2';
    endInput.value = (timeMap[product.id]?.end) || '23:59';
    endInput.dataset.productId = product.id;
    timeDiv.appendChild(startInput);
    timeDiv.appendChild(endInput);

    const pauseGroup = document.createElement('div');
    pauseGroup.className = 'form-check form-switch ms-2';
    const pauseToggle = document.createElement('input');
    pauseToggle.type = 'checkbox';
    pauseToggle.className = 'form-check-input pause-toggle';
    pauseToggle.id = `pause-${recipientId}-${product.id}`;
    pauseToggle.dataset.productId = product.id;
    const paused = recipientSubscriptions.find(s => s.product_id === product.id)?.paused;
    pauseToggle.checked = !!paused;
    const pauseLabel = document.createElement('label');
    pauseLabel.className = 'form-check-label';
    pauseLabel.setAttribute('for', pauseToggle.id);
    pauseLabel.textContent = 'Paused';
    pauseGroup.appendChild(pauseToggle);
    pauseGroup.appendChild(pauseLabel);
    timeDiv.appendChild(pauseGroup);

    listItem.appendChild(timeDiv);

    startInput.disabled = endInput.disabled = pauseToggle.disabled = !mainCheckbox.checked;
    if (pauseToggle.checked) listItem.classList.add('paused');

    modalBodyElement.appendChild(listItem);
  });
}

async function handleSaveAllSubscriptionSettings() {
  const originalBtnText = 'Save All Subscriptions';
  toggleSaveButton(true, originalBtnText);

  const recipientId = currentModalRecipientId;
  const modalBodyElement = document.getElementById('subscriptionModalBody');
  if (!recipientId || !modalBodyElement) {
    showToastNotification('Error: Cannot save settings. Recipient or modal body not found.', 'error');
    toggleSaveButton(false, originalBtnText);
    return;
  }

  const productItems = modalBodyElement.querySelectorAll('.list-group-item');
  const results = [];

  for (const item of productItems) {
    await updateSubscription(item, recipientId, results);
  }

  if (results.length === 0) {
    showToastNotification('No changes to save.', 'info');
    toggleSaveButton(false, originalBtnText);
    initialSubscriptionDataForModal = storeInitialFormStateHelper();
    updateSaveButtonStateHelper(initialSubscriptionDataForModal);
    return;
  }

  summarizeResults(results);

  await _loadSubscriptionsForRecipientAndRenderIntoModal(recipientId, modalBodyElement);

  toggleSaveButton(false, originalBtnText);
  initialSubscriptionDataForModal = storeInitialFormStateHelper();
  updateSaveButtonStateHelper(initialSubscriptionDataForModal);
}

function handleSubscriptionToggle(event) {
  const checkbox = event.target.closest('.subscription-toggle');
  if (checkbox) {
    const item = checkbox.closest('.list-group-item');
    const startInput = item.querySelector('.sub-time-start');
    const endInput = item.querySelector('.sub-time-end');
    const pauseToggle = item.querySelector('.pause-toggle');
    if (startInput && endInput) {
      startInput.disabled = endInput.disabled = !checkbox.checked;
    }
    if (pauseToggle) {
      pauseToggle.disabled = !checkbox.checked;
    }
  }
  updateSaveButtonStateHelper(initialSubscriptionDataForModal);
}

function handlePauseToggle(event) {
  const toggle = event.target.closest('.pause-toggle');
  if (!toggle) return;
  const item = toggle.closest('.list-group-item');
  if (item) {
    if (toggle.checked) item.classList.add('paused');
    else item.classList.remove('paused');
  }
  updateSaveButtonStateHelper(initialSubscriptionDataForModal);
}

async function _fetchSubscriptionDataForRecipient(recipientId) {
  if (!recipientId) return [null, null];
  try {
    const [allProducts, recipientSubscriptions] = await Promise.all([
      fetchAPI('/api/products'),
      fetchAPI(`/api/subscriptions?recipient_id=${recipientId}`)
    ]);
    return [allProducts, recipientSubscriptions];
  } catch (error) {
    console.error(`Error loading subscription data for recipient ${recipientId}:`, error);
    return [null, null];
  }
}

async function _loadSubscriptionsForRecipientAndRenderIntoModal(recipientId, modalBodyElement) {
  modalBodyElement.innerHTML = '<div class="list-group-item">Loading subscriptions...</div>';
  initialSubscribedProductIds.clear();
  const [allProducts, recipientSubscriptions] = await _fetchSubscriptionDataForRecipient(recipientId);
  if (allProducts === null) {
    modalBodyElement.innerHTML = '<div class="list-group-item list-group-item-danger">Error loading subscription data.</div>';
    return;
  }
  if (recipientSubscriptions && recipientSubscriptions.length > 0) {
    recipientSubscriptions.forEach(sub => initialSubscribedProductIds.add(sub.product_id));
  }
  renderSubscriptionProductsInModal(allProducts, recipientSubscriptions || [], recipientId, modalBodyElement);
}

export async function openSubscriptionModal(recipientId, recipientName, recipientPincode) {
  currentModalRecipientId = recipientId;
  const modal = document.getElementById('subscriptionModal');
  const modalTitle = document.getElementById('subscriptionModalHeaderTitle');
  const pincodeEl = document.getElementById('subscriptionModalPincode');
  const modalBody = document.getElementById('subscriptionModalBody');
  if (!modal || !modalTitle || !modalBody) {
    console.error('Subscription modal elements not found in DOM.');
    alert('Error: Subscription UI is not properly initialized.');
    return;
  }
  modalTitle.textContent = `Manage Subscriptions for ${recipientName}`;
  if (pincodeEl) {
    pincodeEl.textContent = recipientPincode ? `Pincode: ${recipientPincode}` : '';
  }
  await _loadSubscriptionsForRecipientAndRenderIntoModal(recipientId, modalBody);
  modal.style.display = 'block';
  initialSubscriptionDataForModal = storeInitialFormStateHelper();
  updateSaveButtonStateHelper(initialSubscriptionDataForModal);
  const saveBtn = document.getElementById('saveAllSubscriptionsBtn');
  if (saveBtn) {
    saveBtn.disabled = false;
    saveBtn.innerHTML = 'Save All Subscriptions';
  }
}

export function initSubscriptionsUI() {
  let modal = document.getElementById('subscriptionModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'subscriptionModal';
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header flex-column align-items-start">
            <h5 class="modal-title" id="subscriptionModalHeaderTitle">Manage Subscriptions</h5>
            <p id="subscriptionModalPincode" class="mb-0 text-muted small"></p>
            <button type="button" class="btn-close position-absolute top-0 end-0 mt-2 me-2" id="subscriptionModalCloseButton" aria-label="Close"></button>
          </div>
          <div class="modal-body" id="subscriptionModalBody"></div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" id="subscriptionModalFooterCloseButton">Close</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }

  const modalCloseButton = document.getElementById('subscriptionModalCloseButton');
  const modalFooterCloseButton = document.getElementById('subscriptionModalFooterCloseButton');
  const closeModal = () => { modal.style.display = 'none'; };
  if (modalCloseButton) modalCloseButton.addEventListener('click', closeModal);
  if (modalFooterCloseButton) modalFooterCloseButton.addEventListener('click', closeModal);

  const modalFooter = modal.querySelector('.modal-footer');
  if (modalFooter) {
    const saveAllButton = document.createElement('button');
    saveAllButton.type = 'button';
    saveAllButton.id = 'saveAllSubscriptionsBtn';
    saveAllButton.className = 'btn btn-outline-primary';
    saveAllButton.textContent = 'Save All Subscriptions';
    saveAllButton.addEventListener('click', () => handleSaveAllSubscriptionSettings());
    modalFooter.appendChild(saveAllButton);
  }

  const modalBody = document.getElementById('subscriptionModalBody');
  if (modalBody) {
    modalBody.addEventListener('change', event => {
      if (event.target.classList.contains('subscription-toggle')) {
        handleSubscriptionToggle(event);
      } else if (event.target.classList.contains('sub-time-start') || event.target.classList.contains('sub-time-end')) {
        updateSaveButtonStateHelper(initialSubscriptionDataForModal);
      }
    });
    modalBody.addEventListener('click', event => {
      if (event.target.classList.contains('pause-toggle')) {
        handlePauseToggle(event);
      }
    });
  }

  window.openSubscriptionModal = openSubscriptionModal;
}
