// This file is now solely responsible for initializing the subscription modal.
// All other UI logic and helper functions have been moved to
// subscription-modal.js and subscription-helpers.js respectively.
// The fetchAPI utility has been moved to utils.js.

import { initSubscriptionsUI } from './subscription-modal.js';

// Initialize the subscriptions UI (which now primarily means the modal)
initSubscriptionsUI();
