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
    const currentSubscription = subscriptionsMap.get(product.id) || {}; // API sends defaults

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
    freqInputsCol.appendChild(createInputElement(`freq-mins-${product.id}`, 'number', currentSubscription.frequency_minutes, 0, 55, 5));
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
    delayInputsCol.appendChild(createInputElement(`delay-mins-${product.id}`, 'number', currentSubscription.delay_minutes, 0, 55, 5));
    delayInputsCol.insertAdjacentHTML('beforeend', '<span class="ms-1 small">M</span>');
    delayDurationRow.appendChild(delayInputsCol);

    settingsGrid.appendChild(delayRow);
    settingsGrid.appendChild(delayDurationRow);

    // Save Button
    const saveButton = document.createElement('button');
    saveButton.textContent = 'Save Settings';
    saveButton.className = 'btn btn-sm btn-outline-primary mt-2 save-subscription-settings-btn';
    saveButton.setAttribute('data-product-id', product.id);
    // recipientId is currentModalRecipientId
    settingsGrid.appendChild(saveButton);

    // Set initial visibility of settings based on main checkbox
    settingsGrid.style.display = mainCheckbox.checked ? 'block' : 'none';

    listItem.appendChild(settingsGrid);
    modalBodyElement.appendChild(listItem);
  });
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
async function handleSubscriptionToggle(event) {
  const checkbox = event.target;
  const productId = checkbox.dataset.productId;
  const recipientId = currentModalRecipientId; // Use global recipient ID

  if (!productId || !recipientId) {
    alert('Could not update subscription: critical information missing.');
    return;
  }

  const isSubscribing = checkbox.checked;
  const modalBody = document.getElementById('subscriptionModalBody');

  try {
    if (isSubscribing) {
      // API defaults will be used for granular settings
      await window.fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipientId, product_id: productId }),
      });
    } else {
      await window.fetchAPI('/api/subscriptions', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipientId, product_id: productId }),
      });
    }
    // Refresh modal content after toggle
    await _loadSubscriptionsForRecipientAndRenderIntoModal(recipientId, modalBody);
  } catch (error) {
    console.error('Error toggling subscription:', error);
    alert(`Failed to update subscription: ${error.message}`);
    checkbox.checked = !isSubscribing; // Revert checkbox on error
  }
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

  // Event delegation for dynamic content within the modal body
  const modalBody = document.getElementById('subscriptionModalBody');
  if (modalBody) {
    modalBody.addEventListener('click', (event) => {
      if (event.target.classList.contains('save-subscription-settings-btn')) {
        handleSaveSubscriptionSettings(event);
      }
    });
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
