// Global variable to store current recipient ID for modal operations
let currentModalRecipientId = null;
// Global variable to store the initial state of the subscription form in the modal
let initialSubscriptionDataForModal = '';
// Global variable to store the set of initially subscribed product IDs for the current modal view
let initialSubscribedProductIds = new Set();

// --- Helper Function to Floor to 15 Minute Interval ---
function floorTo15MinuteInterval(dateObj) {
  if (!(dateObj instanceof Date) || isNaN(dateObj.getTime())) {
    // Handle invalid date input, perhaps return null or throw error
    // For now, let's return a new Date() to avoid downstream errors, though this might not be ideal.
    console.error("Invalid date passed to floorTo15MinuteInterval:", dateObj);
    const validDate = new Date();
    validDate.setSeconds(0);
    validDate.setMilliseconds(0);
    validDate.setMinutes(Math.floor(validDate.getMinutes() / 15) * 15);
    return validDate;
  }
  const newDate = new Date(dateObj.getTime());
  newDate.setSeconds(0);
  newDate.setMilliseconds(0);
  newDate.setMinutes(Math.floor(newDate.getMinutes() / 15) * 15);
  return newDate;
}


// --- Calculate Next Check Times Function (Revised Logic based on last_checked_at and flooring) ---
function calculateNextCheckTimes(lastCheckedAtISO, frequencyDays, frequencyHours, frequencyMinutes, count = 4) {
  const projectedTimes = [];
  const currentDate = new Date(); // For checking if times are on the current day

  function formatTime(date) {
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${hours}:${minutes}`;
  }

  function isSameDayAsCurrent(date) {
    if (!(date instanceof Date) || isNaN(date.getTime())) return false;
    return date.getFullYear() === currentDate.getFullYear() &&
           date.getMonth() === currentDate.getMonth() &&
           date.getDate() === currentDate.getDate();
  }

  let lastCheckedAtDate = null;
  if (lastCheckedAtISO) {
    const parsedDate = new Date(lastCheckedAtISO);
    if (!isNaN(parsedDate.getTime())) {
      lastCheckedAtDate = parsedDate;
    } else {
      console.error("Invalid lastCheckedAtISO date string:", lastCheckedAtISO);
    }
  }

  // Handle Zero Frequency
  if (frequencyDays === 0 && frequencyHours === 0 && frequencyMinutes === 0) {
    let currentTimeBase = lastCheckedAtDate ? new Date(lastCheckedAtDate.getTime() + 15 * 60000) : new Date();
    // If lastCheckedAtDate exists and adding 15 mins makes it past 'now', start from 'now' instead.
    if (lastCheckedAtDate && currentTimeBase < new Date()) {
        currentTimeBase = new Date();
    } else if (!lastCheckedAtDate) { // If no lastCheckedAt, ensure base is not in past
        currentTimeBase = new Date();
    }


    let nextSlot = floorTo15MinuteInterval(currentTimeBase);
    // If nextSlot is still before currentTimeBase (e.g. currentTimeBase is 10:05, nextSlot is 10:00), advance it.
    // This ensures the first slot is >= currentTimeBase.
    if (nextSlot.getTime() < currentTimeBase.getTime() && (currentTimeBase.getMinutes() % 15 !==0) ) {
         nextSlot.setMinutes(nextSlot.getMinutes() + 15); // Advance to the next slot
    }


    while (projectedTimes.length < count) {
      if (isSameDayAsCurrent(nextSlot)) {
        const formatted = formatTime(nextSlot);
        if (!projectedTimes.includes(formatted)) { // Ensure uniqueness
             projectedTimes.push(formatted);
        } else {
            // If it's a duplicate, we still need to advance for the next potential unique slot
        }
      } else {
        // Stop if we cross into another day (or if initial slot is not today)
        if (projectedTimes.length > 0 || nextSlot > currentDate ) break;
      }
      nextSlot.setMinutes(nextSlot.getMinutes() + 15);
    }
    return projectedTimes;
  }

  // Handle Non-Zero Frequency
  let currentBaseTime;

  if (!lastCheckedAtDate) { // New subscription
    currentBaseTime = floorTo15MinuteInterval(new Date());
    if (isSameDayAsCurrent(currentBaseTime)) {
      projectedTimes.push(formatTime(currentBaseTime));
    }
  } else { // Existing subscription
    let theoreticalNextDue = new Date(lastCheckedAtDate.getTime() +
      (frequencyDays * 24 * 60 * 60000) +
      (frequencyHours * 60 * 60000) +
      (frequencyMinutes * 60000));
    currentBaseTime = floorTo15MinuteInterval(theoreticalNextDue);

    // If the calculated first run is in the past, start from now, floored.
    if (currentBaseTime < new Date()) {
        currentBaseTime = floorTo15MinuteInterval(new Date());
    }

    if (isSameDayAsCurrent(currentBaseTime)) {
      projectedTimes.push(formatTime(currentBaseTime));
    }
  }

  // Ensure currentBaseTime is valid before loop, if projectedTimes is empty, it means first slot wasn't today.
  if (projectedTimes.length === 0 && !isSameDayAsCurrent(currentBaseTime)) {
      return []; // First calculated time is not today
  }
   // If projectedTimes is still empty, it means currentBaseTime (from new Date()) was not today, which is impossible.
   // Or, currentBaseTime from existing sub was not today.
   // Ensure currentBaseTime is today if projectedTimes is empty.
   if (projectedTimes.length === 0) {
       currentBaseTime = floorTo15MinuteInterval(new Date()); // Reset to today if all else fails to get a base
       if (isSameDayAsCurrent(currentBaseTime)) {
           projectedTimes.push(formatTime(currentBaseTime));
       } else {
           return []; // Cannot establish a base time for today.
       }
   }


  while (projectedTimes.length < count) {
    let nextTheoreticalDue = new Date(currentBaseTime.getTime() +
      (frequencyDays * 24 * 60 * 60000) +
      (frequencyHours * 60 * 60000) +
      (frequencyMinutes * 60000));
    let nextDisplayedTime = floorTo15MinuteInterval(nextTheoreticalDue);

    if (!isSameDayAsCurrent(nextDisplayedTime)) {
      break; // Stop if we cross to another day
    }

    const formattedNextTime = formatTime(nextDisplayedTime);

    // Handle cases where frequency is small, causing flooring to produce same time
    if (projectedTimes.length > 0 && formattedNextTime === projectedTimes[projectedTimes.length - 1]) {
      // Advance by 15 mins from the *colliding* time to show a different slot
      nextDisplayedTime.setMinutes(nextDisplayedTime.getMinutes() + 15);
      nextDisplayedTime = floorTo15MinuteInterval(nextDisplayedTime); // Re-floor after advancing

      // If advancing pushes it to the next day, break
      if (!isSameDayAsCurrent(nextDisplayedTime)) {
        break;
      }
      // Add the new advanced & floored time if it's different
      const newFormattedTime = formatTime(nextDisplayedTime);
      if (newFormattedTime !== projectedTimes[projectedTimes.length - 1]) {
         projectedTimes.push(newFormattedTime);
      } else {
          // If still same, means we advanced e.g. 10:00 to 10:15, but 10:15 was already there.
          // Or, advancing made it same as a previous entry.
          // To prevent infinite loop, we must ensure currentBaseTime advances.
      }

    } else {
      projectedTimes.push(formattedNextTime);
    }

    currentBaseTime = new Date(nextDisplayedTime.getTime()); // Update base for next iteration to the last valid displayed time

    if (projectedTimes.length >= count) break;
  }
  // Return unique times only (Set conversion handles if any duplicates slipped through complex logic)
  return [...new Set(projectedTimes)];
}

// --- Toast Notification Function ---
function showToastNotification(message, type = 'info', duration = 4000) {
  let toastContainer = document.querySelector('.toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container';
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement('div');
  toast.className = 'toast-notification';
  toast.classList.add(type); // e.g., 'success', 'error', 'warning', 'info'

  toast.textContent = message;

  toastContainer.appendChild(toast);

  // Trigger reflow to ensure transition plays
  void toast.offsetWidth;

  toast.classList.add('show');

  const hideTimeout = setTimeout(() => {
    toast.classList.remove('show');
    toast.addEventListener('transitionend', () => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, { once: true });
  }, duration);

  // Optional: Allow manual close by clicking the toast
  toast.addEventListener('click', () => {
    clearTimeout(hideTimeout);
    toast.classList.remove('show');
    toast.addEventListener('transitionend', () => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, { once: true });
  }, { once: true });
}


// --- Helper functions for Save All Button State Management ---

// Collects the current state of all relevant inputs in the modal
function getModalFormState() {
  const modalBodyElement = document.getElementById('subscriptionModalBody');
  if (!modalBodyElement) return '';

  const formData = {};
  const productItems = modalBodyElement.querySelectorAll('.list-group-item');

  productItems.forEach(item => {
    const mainCheckbox = item.querySelector('.subscription-toggle');
    if (!mainCheckbox) return;

    const productId = mainCheckbox.dataset.productId;
    formData[productId] = {
      subscribed: mainCheckbox.checked,
    };

    if (mainCheckbox.checked) {
      formData[productId].frequency_days = parseInt(document.getElementById(`freq-days-${productId}`)?.value, 10);
      formData[productId].frequency_hours = parseInt(document.getElementById(`freq-hours-${productId}`)?.value, 10);
      formData[productId].frequency_minutes = parseInt(document.getElementById(`freq-mins-${productId}`)?.value, 10);
      formData[productId].delay_on_stock = document.getElementById(`delay-stock-${productId}`)?.checked;
      formData[productId].delay_days = parseInt(document.getElementById(`delay-days-${productId}`)?.value, 10);
      formData[productId].delay_hours = parseInt(document.getElementById(`delay-hours-${productId}`)?.value, 10);
      formData[productId].delay_minutes = parseInt(document.getElementById(`delay-mins-${productId}`)?.value, 10);
    }
  });
  return JSON.stringify(formData);
}

// Stores the current form state as the initial state
function storeInitialFormState() {
  initialSubscriptionDataForModal = getModalFormState();
}

// Updates the "Save All Subscriptions" button based on changes
function updateSaveButtonState() {
  const saveBtn = document.getElementById('saveAllSubscriptionsBtn');
  if (!saveBtn) return;

  const currentState = getModalFormState();
  if (currentState !== initialSubscriptionDataForModal) {
    saveBtn.classList.remove('btn-outline-primary');
    saveBtn.classList.add('btn-primary');
    // saveBtn.textContent = 'Save Changes'; // Optional: change text
  } else {
    saveBtn.classList.remove('btn-primary');
    saveBtn.classList.add('btn-outline-primary');
    // saveBtn.textContent = 'Save All Subscriptions'; // Default text
  }
}


// --- Core UI Rendering and Event Handling ---

// Helper to create input elements
function createInputElement(id, type, value, min, max, step) {
  const input = document.createElement('input');
  input.type = type;
  input.id = id;

  if (type === 'checkbox') {
    input.className = 'form-check-input';
    input.checked = value;
  } else {
    input.className = 'form-control form-control-sm d-inline-block'; // Bootstrap classes
    input.style.width = '70px';
    if (type === 'number') {
      input.value = value;
      if (min !== undefined) input.min = min;
      if (max !== undefined) input.max = max;
      if (step !== undefined) input.step = step;
    }
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
    delayLabel.textContent = "Snooze notifications for this product after it's found in stock:";
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

    // --- Add Next Check Times Display ---
    const nextTimesRow = document.createElement('div');
    nextTimesRow.className = 'row mt-2 mb-2 align-items-center'; // Added mt-2 for spacing
    const nextTimesLabelCol = document.createElement('div');
    nextTimesLabelCol.className = 'col-md-3 col-lg-2'; // Adjusted column for label
    nextTimesLabelCol.innerHTML = `<label class="form-label small">Next checks (today):</label>`;
    nextTimesRow.appendChild(nextTimesLabelCol);

    const nextTimesValuesCol = document.createElement('div');
    nextTimesValuesCol.className = 'col-md-9 col-lg-10'; // Adjusted column for values
    const nextTimesDiv = document.createElement('div');
    nextTimesDiv.id = `next-check-times-${product.id}`;
    nextTimesDiv.className = 'd-flex flex-wrap'; // Use flex for horizontal layout and wrapping

    const calculatedTimes = calculateNextCheckTimes(
      currentSubscription.last_checked_at,
      currentSubscription.frequency_days,
      currentSubscription.frequency_hours,
      currentSubscription.frequency_minutes
    );

    if (calculatedTimes.length > 0) {
      calculatedTimes.forEach(time => {
        const timeSpan = document.createElement('span');
        timeSpan.className = 'badge bg-secondary me-1 mb-1'; // Bootstrap badge for styling
        timeSpan.textContent = time;
        nextTimesDiv.appendChild(timeSpan);
      });
    } else {
      nextTimesDiv.textContent = 'None scheduled for today.';
      nextTimesDiv.className = 'small text-muted'; // Style for this message
    }
    nextTimesValuesCol.appendChild(nextTimesDiv);
    nextTimesRow.appendChild(nextTimesValuesCol);
    settingsGrid.appendChild(nextTimesRow);
    // --- End Next Check Times Display ---


    // Set initial visibility of settings based on main checkbox
    settingsGrid.style.display = mainCheckbox.checked ? 'block' : 'none';

    listItem.appendChild(settingsGrid);
    modalBodyElement.appendChild(listItem);

    // Attach listeners to all inputs within this product item to detect changes
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
        input.addEventListener(eventType, updateSaveButtonState);
      }
    });
  });
}

// Handles saving ALL subscription settings from the modal
async function handleSaveAllSubscriptionSettings() {
  const saveBtn = document.getElementById('saveAllSubscriptionsBtn');
  const originalBtnText = 'Save All Subscriptions'; // Assuming this is the default or desired text

  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...';
  }

  const recipientId = currentModalRecipientId;
  const modalBodyElement = document.getElementById('subscriptionModalBody');

  if (!recipientId || !modalBodyElement) {
    showToastNotification('Error: Cannot save settings. Recipient or modal body not found.', 'error');
    if (saveBtn) { // Restore button if we exit early
        saveBtn.disabled = false;
        saveBtn.innerHTML = originalBtnText;
    }
    return;
  }

  const productItems = modalBodyElement.querySelectorAll('.list-group-item');
  const apiCallPromises = [];

  productItems.forEach(item => {
    const mainCheckbox = item.querySelector('.subscription-toggle');
    if (!mainCheckbox) return;

    const productId = mainCheckbox.dataset.productId;
    const isSubscribed = mainCheckbox.checked;

    if (isSubscribed) {
      // Always POST if checked (API handles create/update)
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
      // Add a function that returns the promise
      apiCallPromises.push(() => window.fetchAPI('/api/subscriptions', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      }).then(data => ({ productId, status: 'fulfilled', data }))
         .catch(error => ({ productId, status: 'rejected', reason: error }))); // Simplified error object
    } else if (initialSubscribedProductIds.has(productId)) {
      // Only DELETE if it was initially subscribed and is now unchecked
      const payload = { recipient_id: recipientId, product_id: productId };
      apiCallPromises.push(() => window.fetchAPI('/api/subscriptions', {
        method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      }).then(data => ({ productId, status: 'fulfilled', data, operation: 'deleted' }))
         .catch(error => ({ productId, status: 'rejected', reason: error })));
    }
    // If not subscribed and was not initially in initialSubscribedProductIds, do nothing.
  });

  if (apiCallPromises.length === 0) {
    showToastNotification("No changes to save.", 'info');
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.innerHTML = originalBtnText;
    }
    storeInitialFormState(); // Update to current (unchanged) state
    updateSaveButtonState();
    return;
  }

  const results = await Promise.allSettled(apiCallPromises.map(p => p()));

  let successCount = 0;
  let errorCount = 0;
  const errorMessages = [];

  results.forEach(result => {
    // Each result from Promise.allSettled will have a status and either 'value' or 'reason'
    // The 'value' here is the object we constructed in our .then/.catch handlers for each promise
    if (result.status === 'fulfilled' && result.value.status === 'fulfilled') {
      successCount++;
    } else if (result.status === 'fulfilled' && result.value.status === 'rejected') {
      // This case handles errors caught by our .catch within the promise function
      errorCount++;
      errorMessages.push(`Product ID ${result.value.productId}: ${result.value.reason.message || 'Failed operation'}`);
    } else if (result.status === 'rejected') {
      // This case handles errors if the promise function itself failed before .then/.catch (less likely here)
      errorCount++;
      // Result.reason might not have productId directly, depends on how it failed.
      // This part might need adjustment based on what 'result.reason' contains.
      errorMessages.push(`Operation failed: ${result.reason.message || 'Unknown error'}`);
    }
  });

  let feedbackMessage = "";
  if (successCount > 0) {
    feedbackMessage += `${successCount} subscription operation(s) processed successfully. `;
  }
  if (errorCount > 0) {
    feedbackMessage += `Encountered ${errorCount} error(s): ${errorMessages.join('; ')}.`;
  } else if (successCount > 0 && errorCount === 0) {
    // feedbackMessage += "All changes saved successfully!"; // Already covered by first part
  } else if (successCount === 0 && errorCount === 0 && apiCallPromises.length > 0) {
     feedbackMessage = "Operations processed, but no specific success/error status was captured for some items.";
  } else if (apiCallPromises.length === 0) { // Should be caught earlier
    feedbackMessage = "No changes to save.";
  }

  // Determine toast type based on counts
  let toastType = 'info'; // Default for "Processing complete" or mixed results not easily categorized
  if (errorCount > 0 && successCount > 0) {
    toastType = 'warning'; // Partial success
  } else if (errorCount > 0 && successCount === 0) {
    toastType = 'error';
  } else if (successCount > 0 && errorCount === 0) {
    toastType = 'success';
  } else if (successCount === 0 && errorCount === 0 && apiCallPromises.length > 0) {
    // This case means all promises settled but didn't match our specific success/error criteria inside the promise values
    // which shouldn't happen with the current promise construction logic.
    // Or, it means operations were attempted but none resulted in a typical "saved" or "error" state we track.
    toastType = 'info'; // Or 'warning' if this state implies uncertainty
    if (!feedbackMessage) feedbackMessage = "Operations processed with undetermined outcomes for some items.";
  }


  if (feedbackMessage.trim()) {
    showToastNotification(feedbackMessage.trim(), toastType);
  } else if (apiCallPromises.length === 0) {
    // This case is already handled by an earlier "No changes to save" toast.
    // However, if it were to be reached, an 'info' toast might be suitable.
    // showToastNotification("No operations were performed.", 'info');
  } else {
     showToastNotification("Processing complete.", toastType);
  }


  // Optionally, refresh the modal to show the persisted state
  if (errorCount === 0 && recipientId && modalBodyElement) {
    // Only reload fully if no errors, to show pristine server state
    await _loadSubscriptionsForRecipientAndRenderIntoModal(recipientId, modalBodyElement);
  }

  // Always restore button state regardless of reload
  if (saveBtn) {
    saveBtn.disabled = false;
    saveBtn.innerHTML = originalBtnText;
  }
  // After saving (or attempting to save), re-capture the form state and update button
  storeInitialFormState(); // Current state becomes the new initial state
  updateSaveButtonState(); // Update button based on this new initial state
}


// Handles saving subscription settings from the modal (DEPRECATED - individual save buttons are removed)
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
  updateSaveButtonState(); // Update button state as toggling is a change
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
  initialSubscribedProductIds.clear(); // Clear for the new recipient

  const [allProducts, recipientSubscriptions] = await _fetchSubscriptionDataForRecipient(recipientId);

  if (allProducts === null) { // Check if fetching failed
    modalBodyElement.innerHTML = `<div class="list-group-item list-group-item-danger">Error loading subscription data.</div>`;
    return;
  }
  if (recipientSubscriptions && recipientSubscriptions.length > 0) {
    recipientSubscriptions.forEach(sub => initialSubscribedProductIds.add(sub.product_id));
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

  // After modal is populated and shown:
  storeInitialFormState(); // Store the initial state of the form
  updateSaveButtonState(); // Set the initial Save button style (should be outline)

  const saveBtn = document.getElementById('saveAllSubscriptionsBtn');
  if (saveBtn) {
    saveBtn.disabled = false; // Ensure enabled
    saveBtn.innerHTML = 'Save All Subscriptions'; // Ensure text is reset
  }
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
    // Initial state should be btn-outline-primary, will be updated by updateSaveButtonState
    saveAllButton.className = 'btn btn-outline-primary';
    saveAllButton.textContent = 'Save All Subscriptions';
    saveAllButton.addEventListener('click', () => handleSaveAllSubscriptionSettings());
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
