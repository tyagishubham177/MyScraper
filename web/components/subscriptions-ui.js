// Global variable to store current recipient ID for modal operations
let currentModalRecipientId = null;
// Global variable to store the initial state of the subscription form in the modal
let initialSubscriptionDataForModal = '';
// Global variable to store the set of initially subscribed product IDs for the current modal view
let initialSubscribedProductIds = new Set();

// --- Helper Function to Floor to 15 Minute Interval ---
function floorTo15MinuteInterval(dateObj) {
  if (!(dateObj instanceof Date) || isNaN(dateObj.getTime())) {
    console.error("Invalid date passed to floorTo15MinuteInterval:", dateObj);
    // Fallback to a valid Date object, floored to the current 15-min interval
    const now = new Date();
    now.setSeconds(0);
    now.setMilliseconds(0);
    now.setMinutes(Math.floor(now.getMinutes() / 15) * 15);
    return now;
  }
  const newDate = new Date(dateObj.getTime());
  newDate.setSeconds(0);
  newDate.setMilliseconds(0);
  newDate.setMinutes(Math.floor(newDate.getMinutes() / 15) * 15);
  return newDate;
}

// --- Helper Function to Format Display String for Dates ---
function formatDisplayString(dateObj, isToday) {
  const hours = dateObj.getHours().toString().padStart(2, '0');
  const minutes = dateObj.getMinutes().toString().padStart(2, '0');
  if (isToday) {
    return `${hours}:${minutes}`;
  } else {
    const year = dateObj.getFullYear();
    const month = (dateObj.getMonth() + 1).toString().padStart(2, '0'); // Months are 0-indexed
    const day = dateObj.getDate().toString().padStart(2, '0');
    // Using "MMM D, HH:MM" for non-today dates for better readability
    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    return `${monthNames[dateObj.getMonth()]} ${day}, ${hours}:${minutes}`;
    // Alternative: return `${year}-${month}-${day} ${hours}:${minutes}`;
  }
}

// --- Calculate Next Check Times Function (Refined Plan) ---
function calculateNextCheckTimes(lastCheckedAtISO, frequencyDays, frequencyHours, frequencyMinutes, maxFutureChecks = 9) { // Changed default to 9
  const checkEvents = [];
  const now = new Date();

  // Helper function, already defined globally but good for clarity if this function were standalone
  function _isToday(dateObj, referenceDate) {
    return dateObj.getFullYear() === referenceDate.getFullYear() &&
           dateObj.getMonth() === referenceDate.getMonth() &&
           dateObj.getDate() === referenceDate.getDate();
  }

  let calculationBaseDate = new Date(now.getTime()); // Use a copy of 'now'

  if (lastCheckedAtISO) {
    const lastCheckedDate = new Date(lastCheckedAtISO);
    if (!isNaN(lastCheckedDate.getTime())) {
      const todayStatus = _isToday(lastCheckedDate, now);
      const displayString = formatDisplayString(lastCheckedDate, todayStatus);
      checkEvents.push({
        timeString: displayString,
        dateObject: new Date(lastCheckedDate.getTime()), // Store a copy
        isPastEvent: true,
        isToday: todayStatus,
      });
      calculationBaseDate = new Date(lastCheckedDate.getTime()); // Base future calculations on this
    } else {
      console.error("Invalid lastCheckedAtISO date string provided:", lastCheckedAtISO);
      // If lastCheckedAtISO is invalid, proceed as if it wasn't provided (base on 'now')
    }
  }

  const totalFrequencyMinutes = (frequencyDays * 24 * 60) + (frequencyHours * 60) + frequencyMinutes;

  // If frequency is zero or invalid, don't calculate future checks beyond the initial lastCheckedAt (if any)
  if (totalFrequencyMinutes <= 0) {
    // If there was no lastCheckedAtISO, and frequency is zero, we might want to show "Next: As soon as possible"
    // or a single upcoming slot from 'now'. For now, returning only past event or empty.
    if (checkEvents.length === 0) { // No last check, and zero frequency
        let nextCheckTime = floorTo15MinuteInterval(new Date(now.getTime()));
        if (nextCheckTime.getTime() < now.getTime()) { // If flooring made it past
            nextCheckTime.setMinutes(nextCheckTime.getMinutes() + 15); // Advance
            nextCheckTime = floorTo15MinuteInterval(nextCheckTime); // Re-floor
        }
        const todayStatus = _isToday(nextCheckTime, now);
        checkEvents.push({
            timeString: formatDisplayString(nextCheckTime, todayStatus),
            dateObject: nextCheckTime,
            isPastEvent: false,
            isToday: todayStatus,
        });
    }
    return checkEvents;
  }

  let futureChecksCount = 0;
  let nextCheckTime = new Date(calculationBaseDate.getTime());

  // "From midnight" principle for the first future check if lastCheckedAtISO was present
  if (lastCheckedAtISO && checkEvents.length > 0) {
    // Start of the day of lastCheckedDate
    const startOfLastCheckedDay = new Date(calculationBaseDate.getFullYear(), calculationBaseDate.getMonth(), calculationBaseDate.getDate());

    // How many full cycles have passed since start of that day up to lastCheckedTime?
    const minutesIntoDayOfLastCheck = (calculationBaseDate.getHours() * 60) + calculationBaseDate.getMinutes();
    const cyclesPassed = Math.floor(minutesIntoDayOfLastCheck / totalFrequencyMinutes);

    // The start of the next cycle
    let nextCycleStartMinutes = (cyclesPassed + 1) * totalFrequencyMinutes;

    // Convert this minute offset back to a date
    nextCheckTime = new Date(startOfLastCheckedDay.getTime() + nextCycleStartMinutes * 60000);

    // If this calculated nextCheckTime is still before or same as calculationBaseDate (lastCheckedDate),
    // it means we need to advance it by one more frequency period.
    if (nextCheckTime.getTime() <= calculationBaseDate.getTime()) {
        nextCheckTime.setMinutes(nextCheckTime.getMinutes() + totalFrequencyMinutes);
    }

  } else { // No lastCheckedAtISO, or it was invalid
    // Start from 'now' but align to the "from midnight" principle for today.
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const minutesIntoToday = (now.getHours() * 60) + now.getMinutes();

    let cyclesSinceMidnight = Math.floor(minutesIntoToday / totalFrequencyMinutes);
    let nextCycleStartMinutesToday = (cyclesSinceMidnight) * totalFrequencyMinutes; // This is the start of current or last cycle

    nextCheckTime = new Date(startOfToday.getTime() + nextCycleStartMinutesToday * 60000);

    // If this time is in the past (relative to 'now'), or exactly 'now' move to the next cycle
    if (nextCheckTime.getTime() <= now.getTime()) {
        nextCheckTime.setMinutes(nextCheckTime.getMinutes() + totalFrequencyMinutes);
    }
  }

  // Always floor the first calculated future time
  nextCheckTime = floorTo15MinuteInterval(nextCheckTime);

  // If the first floored future check is still before 'now', advance it.
  // This can happen if 'now' is e.g. 10:05, freq is 1hr, last check far in past.
  // Midnight logic might give 10:00. We need 11:00.
  // Or if no last check, midnight logic gives 10:00. We need 11:00.
  while (nextCheckTime.getTime() <= now.getTime() && nextCheckTime.getTime() <= calculationBaseDate.getTime() && futureChecksCount < 100 ) { // Add safety break for loop
      // If nextCheckTime is same or before last actual check, advance it.
      // This is critical if lastCheckTime itself was very recent and frequency is small.
      // Also if the initial calculation based on 'now' resulted in a time slot that's already passed or is the current one.
      nextCheckTime.setMinutes(nextCheckTime.getMinutes() + totalFrequencyMinutes);
      nextCheckTime = floorTo15MinuteInterval(nextCheckTime); // Re-floor after adding frequency
  }


  // Generate future checks
  const twoDaysFromNow = new Date(now.getTime() + 2 * 24 * 60 * 60000); // Stop generating if too far

  while (futureChecksCount < maxFutureChecks && nextCheckTime < twoDaysFromNow) {
    // Ensure the slot is actually in the future relative to 'now'
    // (especially for the very first future slot after all adjustments)
    if (nextCheckTime.getTime() > now.getTime()) {
        const todayStatus = _isToday(nextCheckTime, now);
        const displayString = formatDisplayString(nextCheckTime, todayStatus);
        // Avoid duplicate times if frequency is very small compared to 15-min interval
        if (!checkEvents.some(e => e.dateObject.getTime() === nextCheckTime.getTime())) {
            checkEvents.push({
                timeString: displayString,
                dateObject: new Date(nextCheckTime.getTime()), // Store a copy
                isPastEvent: false,
                isToday: todayStatus,
            });
            futureChecksCount++;
        }
    }

    // Calculate next theoretical time based on the current `nextCheckTime`
    nextCheckTime.setMinutes(nextCheckTime.getMinutes() + totalFrequencyMinutes);
    nextCheckTime = floorTo15MinuteInterval(nextCheckTime); // Floor it for the next iteration

    // Safety break for very small frequencies that might not advance `nextCheckTime` enough
    // after flooring, especially if `totalFrequencyMinutes` < 15.
    // The duplicate check above helps, but this is an additional safeguard.
    if (checkEvents.length > 0 && checkEvents[checkEvents.length -1].dateObject.getTime() >= nextCheckTime.getTime()){
        // If the new nextCheckTime isn't greater than the last one added, manually advance by 15 min to find a new slot.
        nextCheckTime.setMinutes(checkEvents[checkEvents.length -1].dateObject.getMinutes() + 15);
        nextCheckTime = floorTo15MinuteInterval(nextCheckTime);

        // If still not advancing (e.g., end of day, crossing 2-day limit), break
        if (checkEvents.length > 0 && checkEvents[checkEvents.length -1].dateObject.getTime() >= nextCheckTime.getTime()){
            break;
        }
    }
  }
  return checkEvents;
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

    // --- Merged Check Times Display ---
    const checkEventsRow = document.createElement('div');
    checkEventsRow.className = 'row mt-2 mb-2 align-items-start'; // align-items-start for better label align if text wraps
    const checkEventsLabelCol = document.createElement('div');
    checkEventsLabelCol.className = 'col-md-3 col-lg-2';
    checkEventsLabelCol.innerHTML = `<label class="form-label small fw-semibold">Event Log & Schedule:</label>`;
    checkEventsRow.appendChild(checkEventsLabelCol);

    const checkEventsValuesCol = document.createElement('div');
    checkEventsValuesCol.className = 'col-md-9 col-lg-10';

    const allCheckEvents = calculateNextCheckTimes(
        currentSubscription.last_checked_at,
        currentSubscription.frequency_days,
        currentSubscription.frequency_hours,
        currentSubscription.frequency_minutes
    );

    const checkTimesBadgesDiv = document.createElement('div');
    checkTimesBadgesDiv.className = 'd-flex flex-wrap';

    if (allCheckEvents.length === 0) {
        const noEventsMsg = document.createElement('span');
        noEventsMsg.textContent = 'Not scheduled.';
        noEventsMsg.className = 'small text-muted';
        checkTimesBadgesDiv.appendChild(noEventsMsg);
    } else {
        const hasPastEvent = allCheckEvents.some(event => event.isPastEvent);
        if (!currentSubscription.last_checked_at && !hasPastEvent) {
            const neverCheckedMsg = document.createElement('div');
            neverCheckedMsg.textContent = 'Never checked. Expected schedule:';
            neverCheckedMsg.className = 'small text-muted mb-1'; // Add margin bottom
            checkEventsValuesCol.appendChild(neverCheckedMsg); // Prepend message
        }

        allCheckEvents.forEach(event => {
            const timeSpan = document.createElement('span');
            // Using badge class for consistent padding/look, but removing default bg
            timeSpan.className = 'badge me-1 mb-1';
            timeSpan.textContent = event.timeString;
            timeSpan.style.marginRight = '5px'; // Explicit margin

            if (event.isPastEvent) {
                timeSpan.style.color = 'white'; // Ensure text is visible on gray
                timeSpan.style.backgroundColor = 'gray';
            } else { // Future event
                if (event.isToday) {
                    timeSpan.style.color = 'white'; // Ensure text is visible
                    timeSpan.style.backgroundColor = 'seagreen';
                } else {
                    timeSpan.style.color = 'black'; // Ensure text is visible on lightgreen
                    timeSpan.style.backgroundColor = 'lightgreen';
                }
            }
            checkTimesBadgesDiv.appendChild(timeSpan);
        });
    }
    checkEventsValuesCol.appendChild(checkTimesBadgesDiv);
    checkEventsRow.appendChild(checkEventsValuesCol);
    settingsGrid.appendChild(checkEventsRow);
    // --- End Merged Check Times Display ---

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


  // Always attempt to refresh the modal to show the persisted state from the server
  if (recipientId && modalBodyElement) {
    await _loadSubscriptionsForRecipientAndRenderIntoModal(recipientId, modalBodyElement);
  }

  // Always restore button state regardless of reload
  if (saveBtn) {
    saveBtn.disabled = false;
    saveBtn.innerHTML = originalBtnText;
  }
  // After saving AND refreshing, re-capture the form state and update button
  storeInitialFormState(); // Current state (fresh from server) becomes the new initial state
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
