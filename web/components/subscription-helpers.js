// --- Helper Function to Floor to 15 Minute Interval ---
export function floorTo15MinuteInterval(dateObj) {
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
export function formatDisplayString(dateObj, isToday) {
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
export function calculateNextCheckTimes(lastCheckedAtISO, frequencyDays, frequencyHours, frequencyMinutes, maxFutureChecks = 9) { // Changed default to 9
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
export function showToastNotification(message, type = 'info', duration = 4000) {
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
export function getModalFormState() {
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
export function storeInitialFormState() {
  // This function now just returns the current state.
  // The assignment to initialSubscriptionDataForModal will happen in the calling module.
  return getModalFormState();
}

// Updates the "Save All Subscriptions" button based on changes
export function updateSaveButtonState(initialSubscriptionDataForModal) {
  // This function now needs to accept the initial state to compare against,
  // as the global variable `initialSubscriptionDataForModal` will be in subscriptions-ui.js
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
export function createInputElement(id, type, value, min, max, step) {
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
