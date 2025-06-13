import {
  calculateNextCheckTimes,
  showToastNotification,
  createInputElement,
  storeInitialFormState as storeInitialFormStateHelper, // Import from helpers
  updateSaveButtonState as updateSaveButtonStateHelper  // Import from helpers
} from './subscription-helpers.js';
import { fetchAPI } from '../utils/utils.js';

// Global variables moved from subscriptions-ui.js
let currentModalRecipientId = null;
let initialSubscriptionDataForModal = '';
let initialSubscribedProductIds = new Set();

// --- Core UI Rendering and Event Handling (Moved from subscriptions-ui.js) ---

function renderSubscriptionProductsInModal(allProducts, recipientSubscriptions, recipientId, modalBodyElement) {
  modalBodyElement.innerHTML = ''; // Clear current list

  if (!allProducts || allProducts.length === 0) {
    modalBodyElement.innerHTML = '<div class="list-group-item">No products available.</div>';
    return;
  }

  const subscribedProductIds = new Set(recipientSubscriptions.map(sub => sub.product_id));
  const subscribedProducts = [];
  const nonSubscribedProducts = [];

  allProducts.forEach(product => {
    if (subscribedProductIds.has(product.id)) {
      subscribedProducts.push(product);
    } else {
      nonSubscribedProducts.push(product);
    }
  });

  const sortedProducts = [...subscribedProducts, ...nonSubscribedProducts];

  const subscriptionsMap = new Map(recipientSubscriptions.map(sub => [sub.product_id, sub]));

  sortedProducts.forEach(product => {
    let currentSubscription = subscriptionsMap.get(product.id);
    const isNewSubscription = !subscriptionsMap.has(product.id);

    if (isNewSubscription) {
      currentSubscription = {}; // Initialize for a new subscription
      currentSubscription.frequency_days = 0;
      currentSubscription.frequency_hours = 0;
      currentSubscription.frequency_minutes = 15;
      currentSubscription.delay_on_stock = false;
      currentSubscription.delay_days = 0; // Default delay days
      currentSubscription.delay_hours = 0; // Default delay hours
      currentSubscription.delay_minutes = 0; // Default delay minutes
    } else if (currentSubscription.frequency_days === undefined) {
      // This handles existing subscriptions that might have incomplete data (fallback)
      // Though ideally, all existing subscriptions should have these fields.
      currentSubscription.frequency_days = currentSubscription.frequency_days || 0;
      currentSubscription.frequency_hours = currentSubscription.frequency_hours || 1;
      currentSubscription.frequency_minutes = currentSubscription.frequency_minutes || 0;
      currentSubscription.delay_on_stock = currentSubscription.delay_on_stock === undefined ? true : currentSubscription.delay_on_stock;
      currentSubscription.delay_days = currentSubscription.delay_days || 1;
      currentSubscription.delay_hours = currentSubscription.delay_hours || 0;
      currentSubscription.delay_minutes = currentSubscription.delay_minutes || 0;
    }


    const listItem = document.createElement('div');
    listItem.className = 'list-group-item mb-3 p-3 border rounded'; // Styling for each product entry

    const mainToggleDiv = document.createElement('div');
    mainToggleDiv.className = 'form-check mb-2';
    const mainCheckbox = createInputElement(`sub-check-${recipientId}-${product.id}`, 'checkbox', !!subscriptionsMap.has(product.id));
    mainCheckbox.classList.add('subscription-toggle'); // Keep this class for event delegation
    mainCheckbox.setAttribute('data-product-id', product.id);

    const mainLabel = document.createElement('label');
    mainLabel.className = 'form-check-label ms-2 fw-bold';
    mainLabel.setAttribute('for', `sub-check-${recipientId}-${product.id}`);
    mainLabel.textContent = product.name;
    mainToggleDiv.appendChild(mainCheckbox);
    mainToggleDiv.appendChild(mainLabel);
    listItem.appendChild(mainToggleDiv);

    const settingsGrid = document.createElement('div');
    settingsGrid.className = 'container-fluid';
    settingsGrid.id = `settings-${recipientId}-${product.id}`;

    const freqRow = document.createElement('div');
    freqRow.className = 'row mb-2 align-items-center';
    freqRow.innerHTML = `<div class="col-md-2"><label class="form-label small">Frequency:</label></div>`;

    const freqInputsCol = document.createElement('div');
    freqInputsCol.className = 'col-md-10 d-flex align-items-center';
    freqInputsCol.appendChild(createInputElement(`freq-days-${product.id}`, 'number', currentSubscription.frequency_days, 0, 7));
    freqInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 me-2 small">D</span>');
    freqInputsCol.appendChild(createInputElement(`freq-hours-${product.id}`, 'number', currentSubscription.frequency_hours, 0, 23));
    freqInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 me-2 small">H</span>');
    const freqMinsSelect = document.createElement('select');
    freqMinsSelect.id = `freq-mins-${product.id}`;
    freqMinsSelect.className = 'form-select form-select-sm d-inline-block';
    freqMinsSelect.style.width = '70px';
    [0, 15, 30, 45].forEach(val => {
      const option = document.createElement('option');
      option.value = val;
      option.textContent = val;
      freqMinsSelect.appendChild(option);
    });
    const currentFreqMins = currentSubscription.frequency_minutes;
    if ([0, 15, 30, 45].includes(currentFreqMins)) {
      freqMinsSelect.value = currentFreqMins;
    } else {
      freqMinsSelect.value = 0;
    }
    freqInputsCol.appendChild(freqMinsSelect);
    freqInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 small">M</span>');
    freqRow.appendChild(freqInputsCol);
    settingsGrid.appendChild(freqRow);

    const delayRow = document.createElement('div');
    delayRow.className = 'row mb-2 align-items-center';
    const delayToggleCol = document.createElement('div');
    delayToggleCol.className = 'col-md-12 mb-2';
    const delayCheckbox = createInputElement(`delay-stock-${product.id}`, 'checkbox', currentSubscription.delay_on_stock);
    const delayLabel = document.createElement('label');
    delayLabel.className = 'form-check-label small ms-2';
    delayLabel.setAttribute('for', `delay-stock-${product.id}`);
    delayLabel.textContent = "Snooze notifications for this product after it's found in stock:";
    delayToggleCol.appendChild(delayCheckbox);
    delayToggleCol.appendChild(delayLabel);
    delayRow.appendChild(delayToggleCol);

    const delayDurationRow = document.createElement('div');
    delayDurationRow.className = 'row mb-2 align-items-center';
    delayDurationRow.innerHTML = `<div class="col-md-2"><label class="form-label small">Delay For:</label></div>`;

    const delayInputsCol = document.createElement('div');
    delayInputsCol.className = 'col-md-10 d-flex align-items-center';
    delayInputsCol.appendChild(createInputElement(`delay-days-${product.id}`, 'number', currentSubscription.delay_days, 0, 7));
    delayInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 me-2 small">D</span>');
    delayInputsCol.appendChild(createInputElement(`delay-hours-${product.id}`, 'number', currentSubscription.delay_hours, 0, 23));
    delayInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 me-2 small">H</span>');
    const delayMinsSelect = document.createElement('select');
    delayMinsSelect.id = `delay-mins-${product.id}`;
    delayMinsSelect.className = 'form-select form-select-sm d-inline-block';
    delayMinsSelect.style.width = '70px';
    [0, 15, 30, 45].forEach(val => {
      const option = document.createElement('option');
      option.value = val;
      option.textContent = val;
      delayMinsSelect.appendChild(option);
    });
    const currentDelayMins = currentSubscription.delay_minutes;
    if ([0, 15, 30, 45].includes(currentDelayMins)) {
      delayMinsSelect.value = currentDelayMins;
    } else {
      delayMinsSelect.value = 0;
    }
    delayInputsCol.appendChild(delayMinsSelect);
    delayInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 small">M</span>');
    delayDurationRow.appendChild(delayInputsCol);
    settingsGrid.appendChild(delayRow);
    settingsGrid.appendChild(delayDurationRow);

    const checkEventsRow = document.createElement('div');
    checkEventsRow.className = 'row mt-2 mb-2 align-items-start';
    const checkEventsLabelCol = document.createElement('div');
    checkEventsLabelCol.className = 'col-md-3 col-lg-2';
    checkEventsLabelCol.innerHTML = `<label class="form-label small fw-semibold">Event Log & Schedule:</label>`;
    checkEventsRow.appendChild(checkEventsLabelCol);

    const checkEventsValuesCol = document.createElement('div');
    checkEventsValuesCol.className = 'col-md-9 col-lg-10';
    const allCheckEvents = calculateNextCheckTimes(
        currentSubscription.last_checked_at,
        currentSubscription.frequency_days,
        currentSubscription.frequency_hours,
        currentSubscription.frequency_minutes
    );
    const checkTimesBadgesDiv = document.createElement('div');
    checkTimesBadgesDiv.className = 'd-flex flex-wrap';
    if (allCheckEvents.length === 0) {
        const noEventsMsg = document.createElement('span');
        noEventsMsg.textContent = 'Not scheduled.';
        noEventsMsg.className = 'small text-muted';
        checkTimesBadgesDiv.appendChild(noEventsMsg);
    } else {
        const hasPastEvent = allCheckEvents.some(event => event.isPastEvent);
        if (!currentSubscription.last_checked_at && !hasPastEvent) {
            const neverCheckedMsg = document.createElement('div');
            neverCheckedMsg.textContent = 'Never checked. Expected schedule:';
            neverCheckedMsg.className = 'small text-muted mb-1';
            checkEventsValuesCol.appendChild(neverCheckedMsg);
        }
        allCheckEvents.forEach(event => {
            const timeSpan = document.createElement('span');
            timeSpan.className = 'badge me-1 mb-1';
            timeSpan.textContent = event.timeString;
            timeSpan.style.marginRight = '5px';
            if (event.isPastEvent) {
                timeSpan.style.color = 'white';
                timeSpan.style.backgroundColor = 'gray';
            } else {
                if (event.isToday) {
                    timeSpan.style.color = 'white';
                    timeSpan.style.backgroundColor = 'seagreen';
                } else {
                    timeSpan.style.color = 'black';
                    timeSpan.style.backgroundColor = 'lightgreen';
                }
            }
            checkTimesBadgesDiv.appendChild(timeSpan);
        });
    }
    checkEventsValuesCol.appendChild(checkTimesBadgesDiv);
    checkEventsRow.appendChild(checkEventsValuesCol);
    settingsGrid.appendChild(checkEventsRow);
    settingsGrid.style.display = mainCheckbox.checked ? 'block' : 'none';
    listItem.appendChild(settingsGrid);
    modalBodyElement.appendChild(listItem);

    const inputsToWatch = [
      mainCheckbox,
      document.getElementById(`freq-days-${product.id}`),
      document.getElementById(`freq-hours-${product.id}`),
      document.getElementById(`freq-mins-${product.id}`),
      document.getElementById(`delay-stock-${product.id}`),
      document.getElementById(`delay-days-${product.id}`),
      document.getElementById(`delay-hours-${product.id}`),
      document.getElementById(`delay-mins-${product.id}`),
    ];
    inputsToWatch.forEach(input => {
      if (input) {
        const eventType = (input.type === 'checkbox' || input.tagName === 'SELECT') ? 'change' : 'input';
        input.addEventListener(eventType, () => updateSaveButtonStateHelper(initialSubscriptionDataForModal));
      }
    });
  });
}

async function handleSaveAllSubscriptionSettings() {
  const saveBtn = document.getElementById('saveAllSubscriptionsBtn');
  const originalBtnText = 'Save All Subscriptions';

  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...';
  }

  const recipientId = currentModalRecipientId;
  const modalBodyElement = document.getElementById('subscriptionModalBody');

  if (!recipientId || !modalBodyElement) {
    showToastNotification('Error: Cannot save settings. Recipient or modal body not found.', 'error');
    if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.innerHTML = originalBtnText;
    }
    return;
  }

  const productItems = modalBodyElement.querySelectorAll('.list-group-item');
  const results = [];

  for (const item of productItems) {
    const mainCheckbox = item.querySelector('.subscription-toggle');
    if (!mainCheckbox) continue;

    const productId = mainCheckbox.dataset.productId;
    const isSubscribed = mainCheckbox.checked;

    try {
      if (isSubscribed) {
        const frequency_days = parseInt(document.getElementById(`freq-days-${productId}`).value, 10);
        const frequency_hours = parseInt(document.getElementById(`freq-hours-${productId}`).value, 10);
        const frequency_minutes = parseInt(document.getElementById(`freq-mins-${productId}`).value, 10);
        const delay_on_stock = document.getElementById(`delay-stock-${productId}`).checked;
        const delay_days = parseInt(document.getElementById(`delay-days-${productId}`).value, 10);
        const delay_hours = parseInt(document.getElementById(`delay-hours-${productId}`).value, 10);
        const delay_minutes = parseInt(document.getElementById(`delay-mins-${productId}`).value, 10);
        const payload = {
          recipient_id: recipientId, product_id: productId,
          frequency_days, frequency_hours, frequency_minutes,
          delay_on_stock, delay_days, delay_hours, delay_minutes,
        };
        const data = await fetchAPI('/api/subscriptions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        results.push({ productId, success: true, data });
      } else if (initialSubscribedProductIds.has(productId)) {
        const payload = { recipient_id: recipientId, product_id: productId };
        const data = await fetchAPI('/api/subscriptions', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        results.push({ productId, success: true, data, operation: 'deleted' });
      }
    } catch (error) {
      showToastNotification(`Failed to update product ${productId}: ${error.message}`, 'error');
      results.push({ productId, success: false, error });
    }
  }

  if (results.length === 0) {
    showToastNotification("No changes to save.", 'info');
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.innerHTML = originalBtnText;
    }
    initialSubscriptionDataForModal = storeInitialFormStateHelper();
    updateSaveButtonStateHelper(initialSubscriptionDataForModal);
    return;
  }
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

  let feedbackMessage = "";
  if (successCount > 0) feedbackMessage += `${successCount} subscription operation(s) processed successfully. `;
  if (errorCount > 0) feedbackMessage += `Encountered ${errorCount} error(s): ${errorMessages.join('; ')}.`;
  else if (successCount === 0 && errorCount === 0 && results.length > 0) feedbackMessage = "Operations processed, but no specific success/error status was captured.";

  let toastType = 'info';
  if (errorCount > 0 && successCount > 0) toastType = 'warning';
  else if (errorCount > 0 && successCount === 0) toastType = 'error';
  else if (successCount > 0 && errorCount === 0) toastType = 'success';

  if (feedbackMessage.trim()) showToastNotification(feedbackMessage.trim(), toastType);
  else if (results.length === 0) { /* Already handled */ }
  else showToastNotification("Processing complete.", toastType);

  if (recipientId && modalBodyElement) {
    await _loadSubscriptionsForRecipientAndRenderIntoModal(recipientId, modalBodyElement);
  }

  if (saveBtn) {
    saveBtn.disabled = false;
    saveBtn.innerHTML = originalBtnText;
  }
  initialSubscriptionDataForModal = storeInitialFormStateHelper();
  updateSaveButtonStateHelper(initialSubscriptionDataForModal);
}

function handleSubscriptionToggle(event) {
  const checkbox = event.target;
  const productId = checkbox.dataset.productId;
  const recipientId = currentModalRecipientId;

  if (!productId || !recipientId) {
    console.error('Could not toggle subscription view: critical information missing.');
    return;
  }
  const settingsGrid = document.getElementById(`settings-${recipientId}-${productId}`);
  if (settingsGrid) {
    settingsGrid.style.display = checkbox.checked ? 'block' : 'none';
  } else {
    console.error(`Settings grid not found for product ${productId}`);
  }
  updateSaveButtonStateHelper(initialSubscriptionDataForModal);
}

async function _fetchSubscriptionDataForRecipient(recipientId) {
  if (!recipientId) {
    console.warn('No recipient ID provided to _fetchSubscriptionDataForRecipient.');
    return [null, null];
  }
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
    modalBodyElement.innerHTML = `<div class="list-group-item list-group-item-danger">Error loading subscription data.</div>`;
    return;
  }
  if (recipientSubscriptions && recipientSubscriptions.length > 0) {
    recipientSubscriptions.forEach(sub => initialSubscribedProductIds.add(sub.product_id));
  }
  renderSubscriptionProductsInModal(allProducts, recipientSubscriptions || [], recipientId, modalBodyElement);
}

export async function openSubscriptionModal(recipientId, recipientName) {
  currentModalRecipientId = recipientId;
  const modal = document.getElementById('subscriptionModal');
  const modalTitle = document.getElementById('subscriptionModalHeaderTitle');
  const modalBody = document.getElementById('subscriptionModalBody');

  if (!modal || !modalTitle || !modalBody) {
    console.error('Subscription modal elements not found in DOM.');
    alert('Error: Subscription UI is not properly initialized.');
    return;
  }

  modalTitle.textContent = `Manage Subscriptions for ${recipientName}`;
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
          <div class="modal-header">
            <h5 class="modal-title" id="subscriptionModalHeaderTitle">Manage Subscriptions</h5>
            <button type="button" class="btn-close" id="subscriptionModalCloseButton" aria-label="Close"></button>
          </div>
          <div class="modal-body" id="subscriptionModalBody">
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" id="subscriptionModalFooterCloseButton">Close</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  const modalCloseButton = document.getElementById('subscriptionModalCloseButton');
  const modalFooterCloseButton = document.getElementById('subscriptionModalFooterCloseButton');
  const closeModal = () => { modal.style.display = 'none'; };
  if(modalCloseButton) modalCloseButton.addEventListener('click', closeModal);
  if(modalFooterCloseButton) modalFooterCloseButton.addEventListener('click', closeModal);

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
    modalBody.addEventListener('change', (event) => {
      if (event.target.classList.contains('subscription-toggle')) {
        handleSubscriptionToggle(event);
      }
    });
  }

  window.openSubscriptionModal = openSubscriptionModal;
  if (window.loadSubscriptionsForRecipient) delete window.loadSubscriptionsForRecipient;
  if (window.clearSubscriptionProducts) delete window.clearSubscriptionProducts;
}

// fetchAPI is now imported from utils.js and used directly.
