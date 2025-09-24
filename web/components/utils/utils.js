export function createRipple(event) {
  const button = event.currentTarget;
  const circle = document.createElement('span');
  const diameter = Math.max(button.clientWidth, button.clientHeight);
  const radius = diameter / 2;
  circle.style.width = circle.style.height = `${diameter}px`;
  const rect = button.getBoundingClientRect();
  circle.style.left = `${event.clientX - rect.left - radius}px`;
  circle.style.top = `${event.clientY - rect.top - radius}px`;
  circle.classList.add('ripple');
  const existing = button.getElementsByClassName('ripple')[0];
  if (existing) existing.remove();
  button.appendChild(circle);
}

export function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

export function sanitizeUrl(url) {
  try {
    const parsed = new URL(url, window.location.origin);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.href;
    }
  } catch (_) {
    // ignore invalid URLs
  }
  return '';
}

export function escapeHTML(str) {
  return str.replace(/[&<>'"]/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

export function cleanLogText(logText) {
  if (!logText) return '';
  const lines = logText.split('\n');
  const cleaned = lines.map(line => {
    let cleanedLine = line.replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\s*/, '');
    cleanedLine = cleanedLine.replace(/^##\[debug\]\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\s*/, '');
    cleanedLine = cleanedLine.replace(/^##\[command\]\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\s*/, '');
    cleanedLine = cleanedLine.replace(/^##\[warning\]\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\s*/, '');
    cleanedLine = cleanedLine.replace(/^##\[error\]\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\s*/, '');
    cleanedLine = cleanedLine.replace(/^##\[.*?\]\s*/, '');
    if (cleanedLine.trim() === '##[endgroup]') return null;
    return cleanedLine;
  }).filter(l => l !== null && l.trim() !== '');
  return cleaned.join('\n');
}

export function formatRunDate(dateString) {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  const day = String(date.getDate()).padStart(2, '0');
  const monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const month = monthNames[date.getMonth()];
  const year = String(date.getFullYear()).slice(-2);
  let hours = date.getHours();
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const ampm = hours >= 12 ? 'PM' : 'AM';
  hours = hours % 12 || 12;
  const formattedHours = String(hours).padStart(2, '0');
  return `${day}-${month}-${year}, ${formattedHours}:${minutes} ${ampm}`;
}

export function getStatusBadge(status, conclusion) {
  let icon = '<i data-lucide="help-circle" class="me-1"></i>';
  let badgeClass = 'bg-secondary-subtle text-secondary-emphasis';
  let statusText = conclusion || status || 'Unknown';
  statusText = statusText.charAt(0).toUpperCase() + statusText.slice(1).replace(/_/g, ' ');
  if (conclusion === 'success') {
    icon = '<i data-lucide="check-circle" class="me-1"></i>';
    badgeClass = 'bg-success-subtle text-success-emphasis';
  } else if (['failure','cancelled','timed_out'].includes(conclusion)) {
    icon = '<i data-lucide="x-circle" class="me-1"></i>';
    badgeClass = 'bg-danger-subtle text-danger-emphasis';
  } else if (['in_progress','queued','pending'].includes(status)) {
    icon = '<i data-lucide="loader-2" class="me-1 spin-icon"></i>';
    badgeClass = 'bg-info-subtle text-info-emphasis';
  }
  return `<span class="badge ${badgeClass} rounded-pill">${icon}${statusText}</span>`;
}

// Extract only the portion of a GitHub log related to the check_stock.py script
// by trimming everything before the script begins outputting.
export function extractCheckStockLog(logText) {
  if (!logText) return '';
  let startIdx = logText.search(/Launching browser/i);
  if (startIdx === -1) {
    startIdx = logText.search(/check_stock\.py/i);
  }
  let trimmed = startIdx !== -1 ? logText.slice(startIdx) : logText;

  const endIdx = trimmed.search(/Run actions\/upload-artifact@v4/i);
  if (endIdx !== -1) {
    trimmed = trimmed.slice(0, endIdx);
  }
  return trimmed;
}

export async function fetchAPI(url, options = {}) {
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
  if (response.status === 204) { // No Content
    return null;
  }
  return response.json();
}

export function showGlobalLoader() {
  const loader = document.getElementById('global-loader');
  if (loader) loader.style.display = 'flex';
}

export function hideGlobalLoader() {
  const loader = document.getElementById('global-loader');
  if (loader) loader.style.display = 'none';
}
