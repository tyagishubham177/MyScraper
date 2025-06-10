// Global variable to store current recipient ID for modal operations
let currentModalRecipientId = null;

// Helper to create input elements
function createInputElement(id, type, value, min, max, step) {
  const input = document.createElement('input');
  input.type = type;
  input.id = id;
  input.className = 'form-control form-control-sm d-inline-block'; // Bootstrap classes
  input.style.width = '70px'; // Adjust width as needed
  if (type === 'number') {
    input.value = value;
    if (min !== undefined) input.min = min;
    if (max !== undefined) input.max = max;
    if (step !== undefined) input.step = step;
  } else if (type === 'checkbox') {
    input.checked = value;
    input.className = 'form-check-input'; // Bootstrap class for checkbox
  }
  return input;
}

// Renders products and their subscription settings within the modal
function renderSubscriptionProductsInModal(allProducts, recipientSubscriptions, recipientId, modalBodyElement) {
  modalBodyElement.innerHTML = ''; // Clear current list

  if (!allProducts || allProducts.length === 0) {
    modalBodyElement.innerHTML = '<div class="list-group-item">No products available.</div>';
    return;
  }

  const subscriptionsMap = new Map(recipientSubscriptions.map(sub => [sub.product_id, sub]));

  allProducts.forEach(product => {
    let currentSubscription = subscriptionsMap.get(product.id);
    const isNewSubscription = !subscriptionsMap.has(product.id);

    if (isNewSubscription || currentSubscription.frequency_days === undefined) {
      currentSubscription = currentSubscription || {}; // Ensure it's an object if it was truly undefined
      currentSubscription.frequency_days = 0;
      currentSubscription.frequency_hours = 1;
      currentSubscription.frequency_minutes = 0;
      currentSubscription.delay_on_stock = true;
      currentSubscription.delay_days = 1;
      currentSubscription.delay_hours = 0;
      currentSubscription.delay_minutes = 0;
    }


    const listItem = document.createElement('div');
    listItem.className = 'list-group-item mb-3 p-3 border rounded'; // Styling for each product entry

    const mainToggleDiv = document.createElement('div');
    mainToggleDiv.className = 'form-check mb-2';
    const mainCheckbox = createInputElement(`sub-check-${recipientId}-${product.id}`, 'checkbox', !!subscriptionsMap.has(product.id));
    mainCheckbox.classList.add('subscription-toggle'); // Keep this class for event delegation
    mainCheckbox.setAttribute('data-product-id', product.id);
    // recipientId is implicitly currentModalRecipientId for modal operations

    const mainLabel = document.createElement('label');
    mainLabel.className = 'form-check-label ms-2 fw-bold';
    mainLabel.setAttribute('for', `sub-check-${recipientId}-${product.id}`);
    mainLabel.textContent = product.name;
    mainToggleDiv.appendChild(mainCheckbox);
    mainToggleDiv.appendChild(mainLabel);
    listItem.appendChild(mainToggleDiv);

    const settingsGrid = document.createElement('div');
    settingsGrid.className = 'container-fluid'; // Bootstrap grid system
    settingsGrid.id = `settings-${recipientId}-${product.id}`;

    // Row for Frequency Settings
    const freqRow = document.createElement('div');
    freqRow.className = 'row mb-2 align-items-center';
    freqRow.innerHTML = `<div class="col-md-2"><label class="form-label small">Frequency:</label></div>`;

    const freqInputsCol = document.createElement('div');
    freqInputsCol.className = 'col-md-10 d-flex align-items-center';

    freqInputsCol.appendChild(createInputElement(`freq-days-${product.id}`, 'number', currentSubscription.frequency_days, 0, 7)); // Max 7 days
    freqInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 me-2 small">D</span>');
    freqInputsCol.appendChild(createInputElement(`freq-hours-${product.id}`, 'number', currentSubscription.frequency_hours, 0, 23));
    freqInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 me-2 small">H</span>');

    // Create select for frequency_minutes
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
    // Set selected value, defaulting to 0 if not one of the options
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

    // Row for Delay Settings
    const delayRow = document.createElement('div');
    delayRow.className = 'row mb-2 align-items-center';
    const delayToggleCol = document.createElement('div');
    delayToggleCol.className = 'col-md-12 mb-2'; // Full width for checkbox
    const delayCheckbox = createInputElement(`delay-stock-${product.id}`, 'checkbox', currentSubscription.delay_on_stock);
    const delayLabel = document.createElement('label');
    delayLabel.className = 'form-check-label small ms-2';
    delayLabel.setAttribute('for', `delay-stock-${product.id}`);
    delayLabel.textContent = 'Delay notifications if item is out of stock?';
    delayToggleCol.appendChild(delayCheckbox);
    delayToggleCol.appendChild(delayLabel);
    delayRow.appendChild(delayToggleCol);

    const delayDurationRow = document.createElement('div'); // New row for duration inputs
    delayDurationRow.className = 'row mb-2 align-items-center';
    delayDurationRow.innerHTML = `<div class="col-md-2"><label class="form-label small">Delay For:</label></div>`;

    const delayInputsCol = document.createElement('div');
    delayInputsCol.className = 'col-md-10 d-flex align-items-center';
    delayInputsCol.appendChild(createInputElement(`delay-days-${product.id}`, 'number', currentSubscription.delay_days, 0, 7)); // Max 7 days
    delayInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 me-2 small">D</span>');
    delayInputsCol.appendChild(createInputElement(`delay-hours-${product.id}`, 'number', currentSubscription.delay_hours, 0, 23));
    delayInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 me-2 small">H</span>');

    // Create select for delay_minutes
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
    // Set selected value, defaulting to 0 if not one of the options
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

    // Set initial visibility of settings based on main checkbox
    settingsGrid.style.display = mainCheckbox.checked ? 'block' : 'none';

    listItem.appendChild(settingsGrid);
    modalBodyElement.appendChild(listItem);
  });
}

// Handles saving ALL subscription settings from the modal
async function handleSaveAllSubscriptionSettings() {
  const recipientId = currentModalRecipientId;
  const modalBodyElement = document.getElementById('subscriptionModalBody');

  if (!recipientId || !modalBodyElement) {
    alert('Error: Cannot save settings. Recipient or modal body not found.');
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
        // Collect values from new granular pickers
        const frequency_days = parseInt(document.getElementById(`freq-days-${productId}`).value, 10);
        const frequency_hours = parseInt(document.getElementById(`freq-hours-${productId}`).value, 10);
        const frequency_minutes = parseInt(document.getElementById(`freq-mins-${productId}`).value, 10);
        const delay_on_stock = document.getElementById(`delay-stock-${productId}`).checked;
        const delay_days = parseInt(document.getElementById(`delay-days-${productId}`).value, 10);
        const delay_hours = parseInt(document.getElementById(`delay-hours-${productId}`).value, 10);
        const delay_minutes = parseInt(document.getElementById(`delay-mins-${productId}`).value, 10);

        const payload = {
          recipient_id: recipientId,
          product_id: productId,
          frequency_days,
          frequency_hours,
          frequency_minutes,
          delay_on_stock,
          delay_days,
          delay_hours,
          delay_minutes,
        };
        await window.fetchAPI('/api/subscriptions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        results.push({ productId, status: 'saved' });
      } else {
        // If not subscribed, check if a subscription exists to delete it
        // This check might be redundant if the backend handles DELETE for non-existent subs gracefully
        // For now, we assume we only send DELETE if it was previously subscribed or could have been.
        await window.fetchAPI('/api/subscriptions', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ recipient_id: recipientId, product_id: productId }),
        });
        results.push({ productId, status: 'deleted' });
      }
    } catch (error) {
      console.error(`Error processing subscription for product ${productId}:`, error);
      results.push({ productId, status: 'error', message: error.message });
    }
  }

  // Feedback to user
  const successfulSaves = results.filter(r => r.status === 'saved').length;
  const successfulDeletes = results.filter(r => r.status === 'deleted').length;
  const errors = results.filter(r => r.status === 'error');

  let feedbackMessage = '';
  if (successfulSaves > 0) feedbackMessage += `${successfulSaves} subscription(s) saved. `;
  if (successfulDeletes > 0) feedbackMessage += `${successfulDeletes} subscription(s) removed. `;
  if (errors.length > 0) {
    feedbackMessage += `\nEncountered ${errors.length} error(s):\n`;
    errors.forEach(err => {
      feedbackMessage += `- Product ID ${err.productId}: ${err.message}\n`;
    });
  }

  if (feedbackMessage) {
    alert(feedbackMessage.trim() || 'No changes were made.');
  } else {
    alert('All settings processed. No changes detected or all operations failed silently.');
  }

  // Optionally, refresh the modal to show the persisted state
  if (errors.length === 0) {
    // This will re-fetch and show the current state from the server.
    _loadSubscriptionsForRecipientAndRenderIntoModal(recipientId, modalBodyElement);
  }
}


// Handles saving subscription settings from the modal
async function handleSaveSubscriptionSettings(event) {
  const button = event.target;
  const productId = button.dataset.productId;
  const recipientId = currentModalRecipientId; // Use global recipient ID for modal

  if (!productId || !recipientId) {
    alert('Error: Product ID or Recipient ID missing.');
    return;
  }

  // Collect values from new granular pickers
  const frequency_days = parseInt(document.getElementById(`freq-days-${productId}`).value, 10);
  const frequency_hours = parseInt(document.getElementById(`freq-hours-${productId}`).value, 10);
  const frequency_minutes = parseInt(document.getElementById(`freq-mins-${productId}`).value, 10);
  const delay_on_stock = document.getElementById(`delay-stock-${productId}`).checked;
  const delay_days = parseInt(document.getElementById(`delay-days-${productId}`).value, 10);
  const delay_hours = parseInt(document.getElementById(`delay-hours-${productId}`).value, 10);
  const delay_minutes = parseInt(document.getElementById(`delay-mins-${productId}`).value, 10);

  const payload = {
    recipient_id: recipientId,
    product_id: productId,
    frequency_days,
    frequency_hours,
    frequency_minutes,
    delay_on_stock,
    delay_days,
    delay_hours,
    delay_minutes,
  };

  try {
    await window.fetchAPI('/api/subscriptions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    alert('Subscription settings saved!');
    // Optionally re-fetch and re-render modal content to confirm, or trust API
    // For now, direct feedback is alert.
  } catch (error) {
    console.error('Error saving subscription settings:', error);
    alert(`Failed to save settings: ${error.message}`);
  }
}

// Handles toggling a subscription from the modal
function handleSubscriptionToggle(event) {
  const checkbox = event.target;
  const productId = checkbox.dataset.productId;
  const recipientId = currentModalRecipientId; // Use global recipient ID

  if (!productId || !recipientId) {
    // This recipientId check might be less critical now if we're not making API calls,
    // but productId is essential for finding the settings grid.
    console.error('Could not toggle subscription view: critical information missing.');
    return;
  }

  const settingsGrid = document.getElementById(`settings-${recipientId}-${productId}`);
  if (settingsGrid) {
    settingsGrid.style.display = checkbox.checked ? 'block' : 'none';
  } else {
    console.error(`Settings grid not found for product ${productId}`);
  }
  // API calls and re-rendering are deferred to "Save All Subscriptions"
}

// Fetches all products and a specific recipient's subscriptions
async function _fetchSubscriptionDataForRecipient(recipientId) {
  if (!recipientId) {
    console.warn('No recipient ID provided to _fetchSubscriptionDataForRecipient.');
    return [null, null]; // Return nulls to indicate failure
  }
  try {
    const [allProducts, recipientSubscriptions] = await Promise.all([
      window.fetchAPI('/api/products'),
      window.fetchAPI(`/api/subscriptions?recipient_id=${recipientId}`)
    ]);
    return [allProducts, recipientSubscriptions];
  } catch (error) {
    console.error(`Error loading subscription data for recipient ${recipientId}:`, error);
    return [null, null]; // Return nulls or throw, depending on desired error handling
  }
}

// Loads data and then renders it into the modal body
async function _loadSubscriptionsForRecipientAndRenderIntoModal(recipientId, modalBodyElement) {
  modalBodyElement.innerHTML = '<div class="list-group-item">Loading subscriptions...</div>';
  const [allProducts, recipientSubscriptions] = await _fetchSubscriptionDataForRecipient(recipientId);

  if (allProducts === null) { // Check if fetching failed
    modalBodyElement.innerHTML = `<div class="list-group-item list-group-item-danger">Error loading subscription data.</div>`;
    return;
  }
  renderSubscriptionProductsInModal(allProducts, recipientSubscriptions || [], recipientId, modalBodyElement);
}


// Public function to open and populate the subscription modal
export async function openSubscriptionModal(recipientId, recipientName) {
  currentModalRecipientId = recipientId; // Store for use in event handlers
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
  modal.style.display = 'block'; // Show modal
}

// Initializes the subscription UI components (Modal based)
export function initSubscriptionsUI() {
  // Create modal structure if it doesn't exist (basic version)
  let modal = document.getElementById('subscriptionModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'subscriptionModal';
    modal.className = 'modal'; // Basic styling class, assuming CSS handles visibility/layout
    modal.innerHTML = `
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="subscriptionModalHeaderTitle">Manage Subscriptions</h5>
            <button type="button" class="btn-close" id="subscriptionModalCloseButton" aria-label="Close"></button>
          </div>
          <div class="modal-body" id="subscriptionModalBody">
            <!-- Subscription products will be rendered here -->
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" id="subscriptionModalFooterCloseButton">Close</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  // Event listeners for modal controls
  const modalCloseButton = document.getElementById('subscriptionModalCloseButton');
  const modalFooterCloseButton = document.getElementById('subscriptionModalFooterCloseButton');

  const closeModal = () => { modal.style.display = 'none'; };
  if(modalCloseButton) modalCloseButton.addEventListener('click', closeModal);
  if(modalFooterCloseButton) modalFooterCloseButton.addEventListener('click', closeModal);

  // Add Save All Subscriptions button to the modal footer
  const modalFooter = modal.querySelector('.modal-footer');
  if (modalFooter) {
    const saveAllButton = document.createElement('button');
    saveAllButton.type = 'button';
    saveAllButton.id = 'saveAllSubscriptionsBtn';
    saveAllButton.className = 'btn btn-primary';
    saveAllButton.textContent = 'Save All Subscriptions';
    saveAllButton.addEventListener('click', () => handleSaveAllSubscriptionSettings()); // Wrapper to call the async function
    modalFooter.appendChild(saveAllButton);
  }

  // Event delegation for dynamic content within the modal body
  const modalBody = document.getElementById('subscriptionModalBody');
  if (modalBody) {
    // Removed event listener for individual save buttons
    modalBody.addEventListener('change', (event) => {
      if (event.target.classList.contains('subscription-toggle')) {
        handleSubscriptionToggle(event);
      }
    });
  }

  // Expose openSubscriptionModal to be called from recipients-ui.js
  window.openSubscriptionModal = openSubscriptionModal;

  // Remove old window assignments if they exist from previous version
  if (window.loadSubscriptionsForRecipient) delete window.loadSubscriptionsForRecipient;
  if (window.clearSubscriptionProducts) delete window.clearSubscriptionProducts;
}


// A basic fetchAPI function, assuming it's not globally available
// If it is globally available from another script, this definition is not needed.
if (!window.fetchAPI) {
  window.fetchAPI = async function(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'An unknown error occurred' }));
      const error = new Error(errorData.message || `HTTP error! status: ${response.status}`);
      error.response = response;
      throw error;
    }
    if (response.status === 204) { // No Content
      return null;
    }
    return response.json();
  };
}
