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

  const subscribedProductIds = new Set(recipientSubscriptions.map(sub => sub.product_id));

  allProducts.forEach(product => {
    const listItem = document.createElement('div');
    listItem.className = 'list-group-item form-check';

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'form-check-input subscription-toggle';
    checkbox.id = `sub-check-${product.id}`;
    checkbox.setAttribute('data-product-id', product.id);
    // recipientId is passed to this function, can also use window.selectedRecipient.id
    checkbox.setAttribute('data-recipient-id', recipientId);
    checkbox.checked = subscribedProductIds.has(product.id);

    const label = document.createElement('label');
    label.className = 'form-check-label';
    label.setAttribute('for', `sub-check-${product.id}`);
    label.textContent = `${product.name} (${product.url})`;

    listItem.appendChild(checkbox);
    listItem.appendChild(label);
    productListDiv.appendChild(listItem);
  });
}

// Handles toggling a subscription
async function handleSubscriptionToggle(event) {
  const checkbox = event.target;
  const productId = checkbox.dataset.productId;
  // Ensure recipientId is correctly sourced, e.g., from window.selectedRecipient
  const recipientId = window.selectedRecipient ? window.selectedRecipient.id : null;

  if (!productId || !recipientId) {
    console.error('Product ID or Recipient ID is missing for subscription toggle.');
    // Optionally revert checkbox state if critical info is missing
    // checkbox.checked = !checkbox.checked;
    alert('Could not update subscription: critical information missing.');
    return;
  }

  const isSubscribing = checkbox.checked;

  try {
    if (isSubscribing) {
      await window.fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipientId, product_id: productId }),
      });
      // console.log(`Subscribed recipient ${recipientId} to product ${productId}`);
    } else {
      await window.fetchAPI('/api/subscriptions', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' }, // Vercel expects body for DELETE
        body: JSON.stringify({ recipient_id: recipientId, product_id: productId }),
      });
      // console.log(`Unsubscribed recipient ${recipientId} from product ${productId}`);
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
    // Event delegation for subscription toggles
    productListDiv.addEventListener('change', (event) => {
      if (event.target.classList.contains('subscription-toggle')) {
        handleSubscriptionToggle(event);
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
