// Globally accessible variable to store selected recipient details
window.selectedRecipient = {
  id: null,
  email: null,
};

const recipientErrorTimers = {}; // To store timeout IDs for recipient error messages

function displayRecipientError(elementId, message, timeout = 5000) {
  const errorElement = document.getElementById(elementId);
  if (!errorElement) {
    console.warn(`Error element with ID ${elementId} not found.`);
    alert(message); // Fallback
    return;
  }

  if (recipientErrorTimers[elementId]) {
    clearTimeout(recipientErrorTimers[elementId]);
  }

  errorElement.innerHTML = message;
  errorElement.classList.add('alert', 'alert-danger');
  errorElement.style.display = 'block';

  recipientErrorTimers[elementId] = setTimeout(() => {
    errorElement.innerHTML = '';
    errorElement.classList.remove('alert', 'alert-danger');
    errorElement.style.display = 'none';
    delete recipientErrorTimers[elementId];
  }, timeout);
}

function clearRecipientError(elementId) {
  const errorElement = document.getElementById(elementId);
  if (!errorElement) return;

  if (recipientErrorTimers[elementId]) {
    clearTimeout(recipientErrorTimers[elementId]);
    delete recipientErrorTimers[elementId];
  }
  errorElement.innerHTML = '';
  errorElement.classList.remove('alert', 'alert-danger');
  errorElement.style.display = 'none';
}

// Function to make API calls (can be generalized later)
async function fetchAPI(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: 'An unknown error occurred' }));
    const error = new Error(errorData.message || `HTTP error! status: ${response.status}`);
    error.response = response; // Attach response for more detailed error handling if needed
    throw error;
  }
  // If response is 204 No Content or other non-JSON success, handle appropriately
  if (response.status === 204) {
    return null; // Or {success: true} or similar, depending on API design
  }
  return response.json();
}

// Renders the list of recipients
function renderRecipientsList(recipients) {
  const recipientsList = document.getElementById('recipients-list');
  const recipientSubscriptionsSection = document.getElementById('recipient-subscriptions-section');
  recipientsList.innerHTML = ''; // Clear current list

  if (!recipients || recipients.length === 0) {
    recipientsList.innerHTML = '<li class="list-group-item">No recipients found.</li>';
    recipientSubscriptionsSection.style.display = 'none'; // Hide if no recipients
    window.selectedRecipient = { id: null, email: null }; // Clear selection
    // Potentially trigger an event or call a function to clear subscription products if needed
    if (window.clearSubscriptionProducts) {
        window.clearSubscriptionProducts();
    }
    return;
  }

  recipients.forEach(recipient => {
    const listItem = document.createElement('li');
    listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
    listItem.setAttribute('data-recipient-id', recipient.id);
    listItem.setAttribute('data-recipient-email', recipient.email);

    const emailSpan = document.createElement('span');
    emailSpan.textContent = recipient.email;
    // emailSpan.style.cursor = 'pointer'; // Removed: Span is not directly clickable for subs
    // emailSpan.title = 'Click to manage subscriptions'; // Removed

    const buttonsDiv = document.createElement('div');
    buttonsDiv.className = 'buttons-div'; // Added class for potential styling

    const manageBtn = document.createElement('button');
    manageBtn.className = 'btn btn-sm btn-outline-primary me-2 manage-subscriptions-btn btn-manage-icon'; // Changed to btn-outline-primary and added icon class
    manageBtn.innerHTML = '<i data-lucide="settings-2"></i>'; // Icon only
    manageBtn.title = 'Manage Subscriptions'; // Add title for accessibility
    manageBtn.setAttribute('data-recipient-id', recipient.id);
    manageBtn.setAttribute('data-recipient-email', recipient.email);


    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-sm btn-outline-danger delete-recipient-btn btn-delete-icon'; // Added icon class
    deleteBtn.innerHTML = '<i data-lucide="trash-2"></i>'; // Icon only
    deleteBtn.title = 'Delete Recipient'; // Add title for accessibility
    deleteBtn.setAttribute('data-recipient-id', recipient.id);

    buttonsDiv.appendChild(manageBtn);
    buttonsDiv.appendChild(deleteBtn);

    listItem.appendChild(emailSpan);
    listItem.appendChild(buttonsDiv);
    recipientsList.appendChild(listItem);
  });
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

// Fetches recipients from the API
async function fetchRecipients() {
  try {
    const recipients = await fetchAPI('/api/recipients');
    renderRecipientsList(recipients);
  } catch (error) {
    console.error('Error fetching recipients:', error);
    const recipientsList = document.getElementById('recipients-list');
    recipientsList.innerHTML = `<li class="list-group-item list-group-item-danger">Error loading recipients: ${error.message}</li>`;
  }
}

// Handles adding a new recipient
async function handleAddRecipient(event) {
  event.preventDefault();
  const emailInput = document.getElementById('recipient-email');
  const email = emailInput.value.trim();
  const errorElementId = 'add-recipient-error-message';

  // Clear previous error messages immediately
  clearRecipientError(errorElementId);

  if (!email) {
    displayRecipientError(errorElementId, 'Please enter an email address.');
    return;
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    displayRecipientError(errorElementId, 'Please enter a valid email address.');
    return;
  }

  try {
    await fetchAPI('/api/recipients', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    emailInput.value = ''; // Clear input
    clearRecipientError(errorElementId); // Clear error message on success
    fetchRecipients(); // Refresh list
  } catch (error) {
    console.error('Error adding recipient:', error);
    displayRecipientError(errorElementId, error.message);
  }
}

// Handles deleting a recipient
async function handleDeleteRecipient(recipientId) {
  if (!recipientId) {
    console.error('No recipient ID provided for deletion.');
    return;
  }
  if (!confirm('Are you sure you want to delete this recipient and all their subscriptions?')) {
    return;
  }

  try {
    await fetchAPI(`/api/recipients?id=${recipientId}`, { method: 'DELETE' });
    fetchRecipients(); // Refresh list
    // If the deleted recipient was the selected one, hide the subscriptions section
    if (window.selectedRecipient && window.selectedRecipient.id === recipientId) {
        document.getElementById('recipient-subscriptions-section').style.display = 'none';
        window.selectedRecipient = { id: null, email: null };
        if (window.clearSubscriptionProducts) {
            window.clearSubscriptionProducts();
        }
    }
  } catch (error) {
    console.error('Error deleting recipient:', error);
    alert(`Failed to delete recipient: ${error.message}`);
  }
}

// Handles showing the manage subscriptions section for a recipient
function handleManageSubscriptions(recipientId, recipientEmail) {
  if (!recipientId || !recipientEmail) {
    console.error('Recipient ID or email not provided for managing subscriptions.');
    return;
  }

  window.selectedRecipient = { id: recipientId, email: recipientEmail };

  // Notify subscriptions-ui.js to open its modal
  if (window.openSubscriptionModal) {
    window.openSubscriptionModal(recipientId, recipientEmail);
  } else {
    console.warn('openSubscriptionModal function not found on window. Subscriptions UI cannot be opened.');
    alert('Subscription management UI is currently unavailable.');
  }
}

// Handles closing the manage subscriptions section
function handleCloseSubscriptions() {
  const subscriptionsSection = document.getElementById('recipient-subscriptions-section');
  if (subscriptionsSection) {
    subscriptionsSection.style.display = 'none';
  }
  window.selectedRecipient = { id: null, email: null };
  if (window.clearSubscriptionProducts) {
    window.clearSubscriptionProducts();
  }
}

// Initializes the recipient UI components
export function initRecipientsUI() {
  const addRecipientBtn = document.getElementById('add-recipient-btn');
  const recipientsList = document.getElementById('recipients-list');
  const closeSubscriptionsBtn = document.getElementById('close-subscriptions-btn');

  if (addRecipientBtn) {
    addRecipientBtn.addEventListener('click', handleAddRecipient);
  }

  // Event delegation for delete and manage buttons
  if (recipientsList) {
    recipientsList.addEventListener('click', (event) => {
      const target = event.target.closest('button.delete-recipient-btn, button.manage-subscriptions-btn, span');

      if (!target) return;

      const recipientId = target.closest('li[data-recipient-id]')?.dataset.recipientId;
      const recipientEmail = target.closest('li[data-recipient-id]')?.dataset.recipientEmail;


      if (target.classList.contains('delete-recipient-btn')) {
        if (recipientId) handleDeleteRecipient(recipientId);
      } else if (target.classList.contains('manage-subscriptions-btn')) { // Only button triggers
         if (recipientId && recipientEmail) handleManageSubscriptions(recipientId, recipientEmail);
      }
    });
  }

  if (closeSubscriptionsBtn) {
    closeSubscriptionsBtn.addEventListener('click', handleCloseSubscriptions);
  }

  fetchRecipients(); // Load initial list
}
