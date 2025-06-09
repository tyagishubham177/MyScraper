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
    productUrl.textContent = product.url;

    productInfoDiv.appendChild(productName);
    productInfoDiv.appendChild(productUrl);

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-sm btn-outline-danger delete-product-btn';
    deleteBtn.innerHTML = '<i class="lucide lucide-trash-2" data-lucide="trash-2"></i> Delete';
    deleteBtn.setAttribute('data-product-id', product.id);

    listItem.appendChild(productInfoDiv);
    listItem.appendChild(deleteBtn);
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
