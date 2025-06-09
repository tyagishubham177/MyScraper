// Re-use or re-define fetchAPI if not globally available
// For this example, let's assume fetchAPI is made available globally or imported from a shared module.
// If not, it should be defined here similar to how it was in recipients-ui.js.
// async function fetchAPI(url, options) { ... }

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

  if (!name || !url) {
    alert('Please enter both product name and URL.');
    return;
  }
  // Basic URL validation
  try {
    new URL(url);
  } catch (_) {
    alert('Please enter a valid URL.');
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
    fetchProducts(); // Refresh list
  } catch (error) {
    console.error('Error adding product:', error);
    alert(`Failed to add product: ${error.message}`);
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

// Initializes the product UI components
export function initProductsUI() {
  const addProductBtn = document.getElementById('add-product-btn');
  const productsListEl = document.getElementById('products-list');

  if (addProductBtn) {
    addProductBtn.addEventListener('click', handleAddProduct);
  }

  // Event delegation for delete buttons
  if (productsListEl) {
    productsListEl.addEventListener('click', (event) => {
      const deleteButton = event.target.closest('button.delete-product-btn');
      if (deleteButton) {
        const productId = deleteButton.dataset.productId;
        if (productId) {
          handleDeleteProduct(productId);
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

      if (!name || !url) {
        alert('Please enter both product name and URL.');
        return;
      }
      try {
        new URL(url); // Basic URL validation
      } catch (_) {
        alert('Please enter a valid URL.');
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
            // Fallback if modal instance is not found, though less ideal.
            // This might indicate an issue with Bootstrap's initialization or timing.
            // For robustness, one might try to re-initialize and hide.
            // However, if Bootstrap is loaded and initialized correctly, getInstance should work.
            console.warn('Modal instance not found for #editProductModal, attempting to hide via new instance.');
            new bootstrap.Modal(editProductModalEl).hide();
          }
        }

      } catch (error) {
        console.error('Error updating product:', error);
        alert(`Failed to update product: ${error.message}`);
        // Optionally, do not hide the modal on error, so the user can retry or correct.
      }
    });
  }
}

// A basic fetchAPI function, assuming it's not globally available from recipients-ui.js
// If it is globally available, this definition is not needed.
if (!window.fetchAPI) {
  window.fetchAPI = async function(url, options) {
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
