// Re-use or re-define fetchAPI if not globally available
// For this example, let's assume fetchAPI is made available globally or imported from a shared module.
// If not, it should be defined here similar to how it was in recipients-ui.js.
// async function fetchAPI(url, options) { ... }

const errorTimers = {}; // To store timeout IDs for error messages

function displayError(elementId, message, timeout = 5000) {
  const errorElement = document.getElementById(elementId);
  if (!errorElement) {
    console.warn(`Error element with ID ${elementId} not found.`);
    // Fallback to alert if element doesn't exist, though ideally it always should.
    alert(message);
    return;
  }

  // Clear existing timeout for this element
  if (errorTimers[elementId]) {
    clearTimeout(errorTimers[elementId]);
  }

  errorElement.textContent = message;
  errorElement.classList.add('alert', 'alert-danger');
  errorElement.style.display = 'block'; // Ensure it's visible

  // Set new timeout
  errorTimers[elementId] = setTimeout(() => {
    errorElement.textContent = '';
    errorElement.classList.remove('alert', 'alert-danger');
    errorElement.style.display = 'none'; // Hide it again
    delete errorTimers[elementId]; // Remove timer ID once done
  }, timeout);
}

function clearError(elementId) {
  const errorElement = document.getElementById(elementId);
  if (!errorElement) return;

  if (errorTimers[elementId]) {
    clearTimeout(errorTimers[elementId]);
    delete errorTimers[elementId];
  }
  errorElement.textContent = '';
  errorElement.classList.remove('alert', 'alert-danger');
  errorElement.style.display = 'none'; // Ensure it's hidden
}


// Renders the list of products
function renderProductsList(products) {
  const productsListEl = document.getElementById('products-list');
  productsListEl.innerHTML = ''; // Clear current list

  if (!products || products.length === 0) {
    productsListEl.innerHTML = '<li class="list-group-item">No products found.</li>';
    return;
  }

  products.forEach(product => {
    const listItem = document.createElement('li');
    listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
    listItem.setAttribute('data-product-id', product.id);

    const productInfoDiv = document.createElement('div');
    const productName = document.createElement('strong');
    productName.textContent = product.name;
    const productUrl = document.createElement('small');
    productUrl.className = 'd-block text-muted';
    // Display URL as a snippet with an external link icon
    const displayUrl = product.url.length > 30 ? product.url.substring(0, 27) + '...' : product.url;
    productUrl.innerHTML = `<a href="${product.url}" target="_blank" title="${product.url}">${displayUrl} <i data-lucide="external-link" class="lucide-small"></i></a>`;

    productInfoDiv.appendChild(productName);
    productInfoDiv.appendChild(productUrl);

    const buttonsDiv = document.createElement('div'); // Create a div for buttons for consistent spacing
    buttonsDiv.className = 'buttons-div';

    const manageBtn = document.createElement('button');
    manageBtn.className = 'btn btn-sm btn-outline-primary me-2 manage-product-subs-btn btn-manage-icon';
    manageBtn.innerHTML = '<i data-lucide="user"></i>';
    manageBtn.title = 'View Subscribers';
    manageBtn.setAttribute('data-product-id', product.id);
    manageBtn.setAttribute('data-product-name', product.name);

    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-sm btn-outline-secondary me-2 btn-edit-icon'; // Added me-2 for spacing from delete
    editBtn.innerHTML = '<i data-lucide="edit"></i>';
    editBtn.title = 'Edit Product';
    editBtn.setAttribute('data-product-id', product.id);
    editBtn.setAttribute('data-product-name', product.name);
    editBtn.setAttribute('data-product-url', product.url);
    editBtn.setAttribute('data-bs-toggle', 'modal');
    editBtn.setAttribute('data-bs-target', '#editProductModal');

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-sm btn-outline-danger delete-product-btn btn-delete-icon'; // Added icon class
    deleteBtn.innerHTML = '<i data-lucide="trash-2"></i>'; // Icon only
    deleteBtn.title = 'Delete Product'; // Add title for accessibility
    deleteBtn.setAttribute('data-product-id', product.id);

    buttonsDiv.appendChild(manageBtn); // Add manage button
    buttonsDiv.appendChild(editBtn); // Add edit button
    buttonsDiv.appendChild(deleteBtn); // Add delete button

    listItem.appendChild(productInfoDiv);
    listItem.appendChild(buttonsDiv); // Add div to list item
    productsListEl.appendChild(listItem);
  });
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

// Fetches products from the API
async function fetchProducts() {
  try {
    // Assuming fetchAPI is globally available or imported
    const products = await window.fetchAPI('/api/products');
    renderProductsList(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    const productsListEl = document.getElementById('products-list');
    productsListEl.innerHTML = `<li class="list-group-item list-group-item-danger">Error loading products: ${error.message}</li>`;
  }
}

// Handles adding a new product
async function handleAddProduct(event) {
  event.preventDefault();
  const nameInput = document.getElementById('product-name');
  const urlInput = document.getElementById('product-url');
  const name = nameInput.value.trim();
  const url = urlInput.value.trim();
  const errorElementId = 'add-product-error-message';

  // Clear previous error messages immediately before new validation/action
  clearError(errorElementId);

  if (!name || !url) {
    displayError(errorElementId, 'Please enter both product name and URL.');
    return;
  }
  // Basic URL validation
  try {
    new URL(url);
  } catch (_) {
    displayError(errorElementId, 'Please enter a valid URL.');
    return;
  }

  try {
    await window.fetchAPI('/api/products', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, url }),
    });
    nameInput.value = ''; // Clear input
    urlInput.value = '';  // Clear input
    clearError(errorElementId); // Clear error message on success
    fetchProducts(); // Refresh list
  } catch (error) {
    console.error('Error adding product:', error);
    displayError(errorElementId, error.message);
  }
}

// Handles deleting a product
async function handleDeleteProduct(productId) {
  if (!productId) {
    console.error('No product ID provided for deletion.');
    return;
  }
  if (!confirm('Are you sure you want to delete this product? This will also remove any subscriptions to it.')) {
    return;
  }

  try {
    await window.fetchAPI(`/api/products?id=${productId}`, { method: 'DELETE' });
    fetchProducts(); // Refresh product list

    // If a recipient is selected and their subscription view is active, refresh it
    // as the deleted product might have been listed there.
    if (window.selectedRecipient && window.selectedRecipient.id && window.loadSubscriptionsForRecipient) {
      window.loadSubscriptionsForRecipient(window.selectedRecipient.id);
    }

  } catch (error) {
    console.error('Error deleting product:', error);
    alert(`Failed to delete product: ${error.message}`);
  }
}

// Handles showing subscribers for a product
async function handleManageSubscribers(productId, productName) {
  const modalEl = document.getElementById('productSubscribersModal');
  const modalTitle = document.getElementById('productSubscribersModalLabel');
  const listEl = document.getElementById('product-subscribers-list');
  if (!modalEl || !modalTitle || !listEl) return;

  modalTitle.textContent = `Subscribers for ${productName}`;
  listEl.innerHTML = '<li class="list-group-item">Loading...</li>';
  const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
  modal.show();

  try {
    const [recipients, subs] = await Promise.all([
      window.fetchAPI('/api/recipients'),
      window.fetchAPI(`/api/subscriptions?product_id=${productId}`)
    ]);
    const recipientMap = new Map(recipients.map(r => [r.id, r.email]));
    const subscriberData = subs
      .map(s => ({ email: recipientMap.get(s.recipient_id), paused: !!s.paused }))
      .filter(item => item.email);
    listEl.innerHTML = '';
    if (subscriberData.length === 0) {
      listEl.innerHTML = '<li class="list-group-item">No subscribers found.</li>';
    } else {
      subscriberData.forEach(sub => {
        const li = document.createElement('li');
        li.className = 'list-group-item' + (sub.paused ? ' paused' : '');
        li.textContent = `${sub.email} - ${sub.paused ? 'Paused' : 'Active'}`;
        listEl.appendChild(li);
      });
    }
    if (window.lucide) window.lucide.createIcons();
  } catch (err) {
    listEl.innerHTML = `<li class="list-group-item list-group-item-danger">Error loading subscribers: ${err.message}</li>`;
  }
}

// Initializes the product UI components
export function initProductsUI() {
  const addProductBtn = document.getElementById('add-product-btn');
  const productsListEl = document.getElementById('products-list');

  if (addProductBtn) {
    addProductBtn.addEventListener('click', handleAddProduct);
  }

  // Event delegation for buttons
  if (productsListEl) {
    productsListEl.addEventListener('click', (event) => {
      const deleteButton = event.target.closest('button.delete-product-btn');
      if (deleteButton) {
        const productId = deleteButton.dataset.productId;
        if (productId) {
          handleDeleteProduct(productId);
        }
        return;
      }

      const manageButton = event.target.closest('button.manage-product-subs-btn');
      if (manageButton) {
        const productId = manageButton.dataset.productId;
        const productName = manageButton.dataset.productName || '';
        if (productId) {
          handleManageSubscribers(productId, productName);
        }
      }
    });
  }

  fetchProducts(); // Load initial list

  // Event listener for Edit Product Modal
  const editProductModalEl = document.getElementById('editProductModal');
  if (editProductModalEl) {
    editProductModalEl.addEventListener('show.bs.modal', function (event) {
      const button = event.relatedTarget; // Button that triggered the modal
      if (!button) return; // Exit if no related target (e.g. modal shown via JS)

      const productId = button.getAttribute('data-product-id');
      const productName = button.getAttribute('data-product-name');
      const productUrl = button.getAttribute('data-product-url');

      const modalProductIdInput = editProductModalEl.querySelector('#edit-product-id');
      const modalProductNameInput = editProductModalEl.querySelector('#edit-product-name');
      const modalProductUrlInput = editProductModalEl.querySelector('#edit-product-url');

      if (modalProductIdInput) modalProductIdInput.value = productId;
      if (modalProductNameInput) modalProductNameInput.value = productName;
      if (modalProductUrlInput) modalProductUrlInput.value = productUrl;
    });
  }

  // Event listener for "Save Changes" button in Edit Product Modal
  const saveChangesBtn = document.getElementById('save-product-changes-btn');
  if (saveChangesBtn) {
    saveChangesBtn.addEventListener('click', async function () {
      const editProductModalEl = document.getElementById('editProductModal'); // Get modal element for hiding
      const productId = document.getElementById('edit-product-id').value;
      const name = document.getElementById('edit-product-name').value.trim();
      const url = document.getElementById('edit-product-url').value.trim();
      const errorModalElementId = 'edit-product-error-message';

      // Clear previous error messages in modal
      clearError(errorModalElementId);

      if (!name || !url) {
        displayError(errorModalElementId, 'Please enter both product name and URL.');
        return;
      }
      try {
        new URL(url); // Basic URL validation
      } catch (_) {
        displayError(errorModalElementId, 'Please enter a valid URL.');
        return;
      }

      try {
        // SERVER-SIDE REQUIREMENT:
        // The backend API endpoint '/api/products' (or '/api/products?id=:id')
        // must be configured to accept HTTP PUT requests to update product details.
        // If it currently returns a "405 Method Not Allowed" error for PUT,
        // the backend route/handler needs to be updated accordingly.
        await window.fetchAPI(`/api/products?id=${productId}`, {
          method: 'PUT', // Assuming PUT for updates
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, url }),
        });

        fetchProducts(); // Refresh the product list to show updated data

        if (editProductModalEl) {
          const modalInstance = bootstrap.Modal.getInstance(editProductModalEl);
          if (modalInstance) {
            modalInstance.hide();
          } else {
            console.warn('Modal instance not found for #editProductModal, attempting to hide via new instance.');
            new bootstrap.Modal(editProductModalEl).hide();
          }
        }
        // Clear error message on success
        clearError(errorModalElementId);

      } catch (error) {
        console.error('Error updating product:', error);
        displayError(errorModalElementId, error.message);
        // Optionally, do not hide the modal on error, so the user can retry or correct.
      }
    });
  }
}

// A basic fetchAPI function, assuming it's not globally available from recipients-ui.js
// If it is globally available, this definition is not needed.
if (!window.fetchAPI) {
  window.fetchAPI = async function(url, options = {}) {
    options.headers = options.headers || {};
    const token = localStorage.getItem('authToken');
    if (token) {
      options.headers['Authorization'] = `Bearer ${token}`;
    }
    const response = await fetch(url, options);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'An unknown error occurred' }));
      const error = new Error(errorData.message || `HTTP error! status: ${response.status}`);
      error.response = response;
      throw error;
    }
    if (response.status === 204) {
      return null;
    }
    return response.json();
  };
}
