// Assuming window.fetchAPI is available from a previous script (recipients-ui.js or products-ui.js)
// If not, it should be defined here or imported.

// Renders the list of products with subscription toggles
function renderSubscriptionProducts(allProducts, recipientSubscriptions, recipientId) {
  const productListDiv = document.getElementById('subscription-product-list');
  productListDiv.innerHTML = ''; // Clear current list

  if (!allProducts || allProducts.length === 0) {
    productListDiv.innerHTML = '<div class="list-group-item">No products available to subscribe to.</div>';
    return;
  }

  // Create a map for quick lookup of subscription details by product_id
  const subscriptionsMap = new Map(recipientSubscriptions.map(sub => [sub.product_id, sub]));

  allProducts.forEach(product => {
    const listItem = document.createElement('div');
    listItem.className = 'list-group-item'; // Main container for product info and settings

    const productInfoDiv = document.createElement('div');
    productInfoDiv.className = 'form-check'; // For checkbox and label

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'form-check-input subscription-toggle';
    checkbox.id = `sub-check-${product.id}`;
    checkbox.setAttribute('data-product-id', product.id);
    checkbox.setAttribute('data-recipient-id', recipientId);
    const currentSubscription = subscriptionsMap.get(product.id);
    checkbox.checked = !!currentSubscription;

    const label = document.createElement('label');
    label.className = 'form-check-label';
    label.setAttribute('for', `sub-check-${product.id}`);
    label.textContent = product.name;

    productInfoDiv.appendChild(checkbox);
    productInfoDiv.appendChild(label);
    listItem.appendChild(productInfoDiv);

    // Container for additional settings, shown if subscribed
    const settingsDiv = document.createElement('div');
    settingsDiv.className = 'subscription-settings mt-2 ms-4'; // Added ms-4 for indentation
    settingsDiv.id = `settings-${product.id}`;
    // settingsDiv.style.display = checkbox.checked ? 'block' : 'none'; // Show/hide based on subscription

    // Frequency dropdown
    const freqLabel = document.createElement('label');
    freqLabel.setAttribute('for', `freq-${product.id}`);
    freqLabel.textContent = 'Frequency:';
    freqLabel.className = 'form-label me-2';
    const freqSelect = document.createElement('select');
    freqSelect.id = `freq-${product.id}`;
    freqSelect.className = 'form-select form-select-sm d-inline-block w-auto me-3';
    ["hourly", "every_2_hours", "daily", "weekly"].forEach(f => {
      const option = document.createElement('option');
      option.value = f;
      option.textContent = f.replace('_', ' ');
      freqSelect.appendChild(option);
    });
    freqSelect.value = currentSubscription?.frequency || 'daily';

    // Delay on stock checkbox
    const delayStockDiv = document.createElement('div');
    delayStockDiv.className = 'form-check form-check-inline';
    const delayStockCheckbox = document.createElement('input');
    delayStockCheckbox.type = 'checkbox';
    delayStockCheckbox.id = `delay-stock-${product.id}`;
    delayStockCheckbox.className = 'form-check-input';
    delayStockCheckbox.checked = currentSubscription?.delay_on_stock || false;
    const delayStockLabel = document.createElement('label');
    delayStockLabel.setAttribute('for', `delay-stock-${product.id}`);
    delayStockLabel.textContent = 'Delay if item out of stock?';
    delayStockLabel.className = 'form-check-label';
    delayStockDiv.appendChild(delayStockCheckbox);
    delayStockDiv.appendChild(delayStockLabel);

    // Delay duration input
    const delayDurationLabel = document.createElement('label');
    delayDurationLabel.setAttribute('for', `delay-duration-${product.id}`);
    delayDurationLabel.textContent = 'Delay duration:';
    delayDurationLabel.className = 'form-label me-2';
    const delayDurationInput = document.createElement('input');
    delayDurationInput.type = 'text';
    delayDurationInput.id = `delay-duration-${product.id}`;
    delayDurationInput.className = 'form-control form-control-sm d-inline-block w-auto me-3';
    delayDurationInput.value = currentSubscription?.delay_duration || '1_day';
    delayDurationInput.placeholder = "e.g., 1_day, 3_hours";

    // Save button
    const saveButton = document.createElement('button');
    saveButton.textContent = 'Save Settings';
    saveButton.className = 'btn btn-sm btn-outline-primary save-subscription-settings-btn';
    saveButton.setAttribute('data-product-id', product.id);
    saveButton.setAttribute('data-recipient-id', recipientId);

    settingsDiv.appendChild(freqLabel);
    settingsDiv.appendChild(freqSelect);
    settingsDiv.appendChild(delayStockDiv); // Inline checkbox with label
    settingsDiv.appendChild(delayDurationLabel);
    settingsDiv.appendChild(delayDurationInput);
    settingsDiv.appendChild(saveButton);

    // Add a little note for duration input
    const durationNote = document.createElement('small');
    durationNote.className = 'form-text text-muted d-block mt-1';
    durationNote.textContent = 'Duration examples: "1_day", "12_hours", "30_minutes".';
    settingsDiv.appendChild(durationNote);

    listItem.appendChild(settingsDiv);
    productListDiv.appendChild(listItem);
  });
}


// Handles saving subscription settings
async function handleSaveSubscriptionSettings(event) {
  const button = event.target;
  const productId = button.dataset.productId;
  const recipientId = button.dataset.recipientId || (window.selectedRecipient ? window.selectedRecipient.id : null);

  if (!productId || !recipientId) {
    alert('Error: Product ID or Recipient ID missing.');
    return;
  }

  const frequency = document.getElementById(`freq-${productId}`).value;
  const delayOnStock = document.getElementById(`delay-stock-${productId}`).checked;
  const delayDuration = document.getElementById(`delay-duration-${productId}`).value;

  try {
    await window.fetchAPI('/api/subscriptions', {
      method: 'POST', // Assuming API's POST handles update if subscription exists
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipient_id: recipientId,
        product_id: productId,
        frequency: frequency,
        delay_on_stock: delayOnStock,
        delay_duration: delayDuration,
      }),
    });
    alert('Subscription settings saved!');
    // Optionally, reload subscriptions to confirm changes, though API response should be sufficient
    // await _loadSubscriptionsForRecipient(recipientId);
  } catch (error) {
    console.error('Error saving subscription settings:', error);
    alert(`Failed to save settings: ${error.message}`);
  }
}


// Handles toggling a subscription
async function handleSubscriptionToggle(event) {
  const checkbox = event.target;
  const productId = checkbox.dataset.productId;
  const recipientId = window.selectedRecipient ? window.selectedRecipient.id : null;
  // const settingsDiv = document.getElementById(`settings-${productId}`);

  if (!productId || !recipientId) {
    console.error('Product ID or Recipient ID is missing for subscription toggle.');
    alert('Could not update subscription: critical information missing.');
    return;
  }

  const isSubscribing = checkbox.checked;

  try {
    if (isSubscribing) {
      // Create new subscription with default settings
      await window.fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipient_id: recipientId,
          product_id: productId,
          frequency: "daily", // Default
          delay_on_stock: false, // Default
          delay_duration: "1_day" // Default
        }),
      });
      // console.log(`Subscribed recipient ${recipientId} to product ${productId} with default settings`);
      // After successful subscription, reload to show settings with defaults
      // This will also make the settingsDiv visible if it was previously hidden by style.display
      await _loadSubscriptionsForRecipient(recipientId);
    } else {
      await window.fetchAPI('/api/subscriptions', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipientId, product_id: productId }),
      });
      // console.log(`Unsubscribed recipient ${recipientId} from product ${productId}`);
      // After successful unsubscription, reload to hide/update settings
      await _loadSubscriptionsForRecipient(recipientId);
    }
  } catch (error) {
    console.error('Error toggling subscription:', error);
    alert(`Failed to update subscription: ${error.message}`);
    // Revert checkbox state on error to reflect actual state
    checkbox.checked = !isSubscribing;
  }
}

// Loads all products and the recipient's subscriptions, then renders them
async function _loadSubscriptionsForRecipient(recipientId) {
  if (!recipientId) {
    console.warn('No recipient ID provided to loadSubscriptionsForRecipient.');
    clearSubscriptionProducts(); // Clear display if no recipient
    return;
  }

  const productListDiv = document.getElementById('subscription-product-list');
  productListDiv.innerHTML = '<div class="list-group-item">Loading subscriptions...</div>'; // Loading state

  try {
    // Parallel fetch: all products and specific recipient's subscriptions
    const [allProducts, recipientSubscriptions] = await Promise.all([
      window.fetchAPI('/api/products'),
      window.fetchAPI(`/api/subscriptions?recipient_id=${recipientId}`)
    ]);

    renderSubscriptionProducts(allProducts, recipientSubscriptions, recipientId);
  } catch (error) {
    console.error(`Error loading subscriptions for recipient ${recipientId}:`, error);
    productListDiv.innerHTML = `<div class="list-group-item list-group-item-danger">Error loading subscriptions: ${error.message}</div>`;
  }
}

// Clears the subscription product list
function _clearSubscriptionProducts() {
  const productListDiv = document.getElementById('subscription-product-list');
  if (productListDiv) {
    productListDiv.innerHTML = '';
  }
  // Optionally hide the entire section if desired
  // const subscriptionsSection = document.getElementById('recipient-subscriptions-section');
  // if (subscriptionsSection) {
  //   subscriptionsSection.style.display = 'none';
  // }
}

// Initializes the subscription UI components
export function initSubscriptionsUI() {
  // Assign functions to window object so they can be called from recipients-ui.js
  window.loadSubscriptionsForRecipient = _loadSubscriptionsForRecipient;
  window.clearSubscriptionProducts = _clearSubscriptionProducts;

  const productListDiv = document.getElementById('subscription-product-list');
  if (productListDiv) {
    // Event delegation for subscription toggles and save buttons
    productListDiv.addEventListener('click', (event) => {
      if (event.target.classList.contains('save-subscription-settings-btn')) {
        handleSaveSubscriptionSettings(event);
      }
    });
    productListDiv.addEventListener('change', (event) => {
      if (event.target.classList.contains('subscription-toggle')) {
        handleSubscriptionToggle(event);
        // Toggle visibility of settings based on checkbox state
        // const productId = event.target.dataset.productId;
        // const settingsDiv = document.getElementById(`settings-${productId}`);
        // if (settingsDiv) {
        //   settingsDiv.style.display = event.target.checked ? 'block' : 'none';
        // }
      }
    });
  }
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
