import { fetchAPI, showGlobalLoader, hideGlobalLoader, sanitizeUrl, normalizeEmail } from '../utils/utils.js';

export async function initUserSubscriptionsUI() {
  showGlobalLoader();
  const storedEmail = localStorage.getItem('userEmail');
  const displayEmail = localStorage.getItem('userEmailDisplay') || storedEmail;
  const email = normalizeEmail(storedEmail);
  if (!email) {
    window.location.href = '../../index.html';
    return;
  }
  if (storedEmail !== email) {
    localStorage.setItem('userEmail', email);
  }
  if (displayEmail && displayEmail !== storedEmail) {
    localStorage.setItem('userEmailDisplay', displayEmail);
  }

  const legacySuffix = displayEmail && displayEmail !== email ? displayEmail : null;
  if (legacySuffix) {
    const legacyRecipient = localStorage.getItem(`recipientId_${legacySuffix}`);
    if (legacyRecipient && !localStorage.getItem(`recipientId_${email}`)) {
      localStorage.setItem(`recipientId_${email}`, legacyRecipient);
    }
    const legacyPin = localStorage.getItem(`pincode_${legacySuffix}`);
    if (legacyPin && !localStorage.getItem(`pincode_${email}`)) {
      localStorage.setItem(`pincode_${email}`, legacyPin);
    }
  }

  let [recipients, products] = await Promise.all([
    fetchAPI('/api/recipients'),
    fetchAPI('/api/products')
  ]).catch(() => [null, null]);

  if (!recipients || !products) {
    console.error('Failed to load data');
    return;
  }

  const recipient = recipients.find(r => normalizeEmail(r.email) === email);
  if (!recipient) {
    console.error('Recipient not found');
    return;
  }
  localStorage.setItem(`recipientId_${email}`, recipient.id);
  if (legacySuffix) {
    localStorage.removeItem(`recipientId_${legacySuffix}`);
  }
  if (recipient.pincode) {
    localStorage.setItem(`pincode_${email}`, recipient.pincode);
    if (legacySuffix) {
      localStorage.removeItem(`pincode_${legacySuffix}`);
    }
  }

  let subscriptions = await fetchAPI(`/api/subscriptions?recipient_id=${recipient.id}`).catch(() => []);
  const subscribedMap = new Map(subscriptions.map(s => [s.product_id, { ...s, paused: !!s.paused }]));
  const productMap = new Map(products.map(p => [p.id, p]));

  const subscribedList = document.getElementById('user-subscribed-list');
  const allList = document.getElementById('all-products-list');
  const searchInput = document.getElementById('product-search');
  const productsCollapse = document.getElementById('availableProductsPanel');
  const subscribedCollapse = document.getElementById('userSubscribedPanel');

  const collapsibleSections = [productsCollapse, subscribedCollapse].filter(Boolean);
  const collapseToggleMap = new Map();

  const toggleButtons = typeof document?.querySelectorAll === 'function'
    ? Array.from(document.querySelectorAll('.panel-toggle[data-collapsible-target]'))
    : [];

  toggleButtons.forEach(btn => {
    collapseToggleMap.set(btn.dataset.collapsibleTarget, btn);
  });

  function updateCollapseMode() {
    if (typeof bootstrap === 'undefined' || !bootstrap.Collapse) return;
    const viewportWidth = typeof window !== 'undefined' && typeof window.innerWidth === 'number'
      ? window.innerWidth
      : 1200;
    const isMobile = viewportWidth < 1200;

    collapsibleSections.forEach(section => {
      const selector = `#${section.id}`;
      const toggle = collapseToggleMap.get(selector);
      if (!toggle) return;

      const collapseInstance = bootstrap.Collapse.getOrCreateInstance(section, { toggle: false });

      if (isMobile) {
        toggle.setAttribute('data-bs-target', selector);
        toggle.setAttribute('data-bs-toggle', 'collapse');
        toggle.classList.remove('desktop-static');
        toggle.setAttribute('aria-expanded', section.classList.contains('show') ? 'true' : 'false');
      } else {
        toggle.removeAttribute('data-bs-target');
        toggle.removeAttribute('data-bs-toggle');
        toggle.classList.add('desktop-static');
        collapseInstance.show();
        toggle.setAttribute('aria-expanded', 'true');
      }
    });
  }

  collapsibleSections.forEach(section => {
    const selector = `#${section.id}`;
    const toggle = collapseToggleMap.get(selector);
    if (!toggle) return;
    section.addEventListener('show.bs.collapse', () => toggle.setAttribute('aria-expanded', 'true'));
    section.addEventListener('hide.bs.collapse', () => toggle.setAttribute('aria-expanded', 'false'));
  });

  if (typeof window?.addEventListener === 'function') {
    window.addEventListener('resize', updateCollapseMode);
  }
  updateCollapseMode();

  function createSubscribedItem(product, sub, paused = false) {
    const li = document.createElement('li');
    li.className = 'list-group-item bg-glass border-glass rounded-4 p-3 d-flex flex-column gap-3 position-relative overflow-hidden' + (paused ? ' opacity-50' : '');
    li.dataset.productId = product.id;
    li.dataset.name = product.name.toLowerCase();
    
    // Add glowing border effect if active
    if (!paused) {
      const glow = document.createElement('div');
      glow.className = 'position-absolute top-0 start-0 w-100 h-100 pointer-events-none rounded-4';
      glow.style.boxShadow = 'inset 0 0 20px rgba(96, 165, 250, 0.1)';
      glow.style.border = '1px solid rgba(96, 165, 250, 0.3)';
      li.appendChild(glow);
    }

    const details = document.createElement('div');
    details.className = 'product-details d-flex flex-column z-1';
    
    const nameWrapper = document.createElement('div');
    nameWrapper.className = 'product-heading-row d-flex align-items-center justify-content-between mb-1';
    
    const nameEl = document.createElement('h5');
    nameEl.className = 'product-name mb-0 fw-semibold text-white tracking-wide';
    nameEl.textContent = product.name;
    
    const statusBadge = document.createElement('span');
    statusBadge.className = `subscription-status badge rounded-pill ${paused ? 'bg-secondary text-light is-paused' : 'bg-primary bg-opacity-25 text-primary border border-primary border-opacity-50 is-active'}`;
    statusBadge.style.fontSize = '10px';
    statusBadge.textContent = paused ? 'SUSPENDED' : 'ACTIVE';
    
    nameWrapper.appendChild(nameEl);
    nameWrapper.appendChild(statusBadge);

    const linkEl = document.createElement('a');
    const safeUrl = sanitizeUrl(product.url);
    linkEl.href = safeUrl || '#';
    linkEl.target = '_blank';
    linkEl.className = 'product-url d-inline-flex align-items-center gap-1 text-muted text-decoration-none small hover-white transition-all';
    linkEl.title = product.url;
    const displayUrl = product.url.length > 35 ? product.url.substring(0, 32) + '...' : product.url;
    
    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', 'external-link');
    icon.style.width = '14px';
    icon.style.height = '14px';
    
    linkEl.textContent = displayUrl;
    linkEl.appendChild(icon);
    
    details.appendChild(nameWrapper);
    details.appendChild(linkEl);

    const controls = document.createElement('div');
    controls.className = 'product-controls d-flex align-items-center justify-content-between pt-2 border-top border-glass z-1';
    
    controls.innerHTML = `
      <div class="d-flex align-items-center gap-2">
        <div class="d-flex align-items-center bg-dark bg-opacity-50 rounded-pill px-2 py-1 border border-glass time-slot-group">
          <i data-lucide="sun" class="text-warning" style="width:14px;height:14px;"></i>
          <input type="time" class="form-control form-control-sm sub-start bg-transparent border-0 text-white shadow-none fs-7 p-0 ms-2" value="${sub.start_time || '00:00'}" style="width:auto; font-family:var(--font-display);">
        </div>
        <span class="text-muted small">to</span>
        <div class="d-flex align-items-center bg-dark bg-opacity-50 rounded-pill px-2 py-1 border border-glass time-slot-group">
          <i data-lucide="moon" class="text-info" style="width:14px;height:14px;"></i>
          <input type="time" class="form-control form-control-sm sub-end bg-transparent border-0 text-white shadow-none fs-7 p-0 ms-2" value="${sub.end_time || '23:59'}" style="width:auto; font-family:var(--font-display);">
        </div>
      </div>
      <div class="d-flex gap-2 control-actions">
        <button class="btn btn-sm ${paused ? 'btn-outline-success' : 'btn-outline-warning'} rounded-circle pause-btn p-2 d-flex align-items-center justify-content-center" title="${paused ? 'Resume Tracking' : 'Suspend Tracking'}"><i data-lucide="${paused ? 'play' : 'pause'}" style="width:16px;height:16px;"></i></button>
        <button class="btn btn-sm btn-outline-danger rounded-circle unsub-btn p-2 d-flex align-items-center justify-content-center" title="Remove Asset"><i data-lucide="x" style="width:16px;height:16px;"></i></button>
      </div>`;

    li.appendChild(details);
    li.appendChild(controls);
    return li;
  }

  function createAllProductItem(product) {
    const li = document.createElement('li');
    li.className = 'list-group-item bg-glass border-glass rounded-4 p-3 d-flex justify-content-between align-items-center gap-3 transition-all hover-glow';
    li.dataset.productId = product.id;
    li.dataset.name = product.name.toLowerCase();

    const info = document.createElement('div');
    info.className = 'd-flex flex-column overflow-hidden';
    
    const strong = document.createElement('strong');
    strong.className = 'text-white fw-medium text-truncate mb-1';
    strong.textContent = product.name;
    
    const link = document.createElement('small');
    link.className = 'd-flex align-items-center gap-1 text-muted text-truncate';
    
    const displayUrl = product.url.length > 40 ? product.url.substring(0, 37) + '...' : product.url;
    const anchor = document.createElement('a');
    const safeUrl = sanitizeUrl(product.url);
    anchor.href = safeUrl || '#';
    anchor.target = '_blank';
    anchor.title = product.url;
    anchor.className = 'text-muted text-decoration-none hover-white';
    anchor.textContent = displayUrl;
    
    const icon2 = document.createElement('i');
    icon2.setAttribute('data-lucide', 'external-link');
    icon2.style.width = '12px';
    icon2.style.height = '12px';
    
    anchor.appendChild(icon2);
    link.appendChild(anchor);
    
    info.appendChild(strong);
    info.appendChild(link);

    const btn = document.createElement('button');
    btn.className = 'btn btn-sm btn-primary rounded-circle sub-btn p-2 d-flex align-items-center justify-content-center flex-shrink-0';
    btn.title = 'Track Asset';
    btn.innerHTML = '<i data-lucide="plus" style="width:18px;height:18px;"></i>';

    li.appendChild(info);
    li.appendChild(btn);
    return li;
  }

  function render() {
    subscribedList.innerHTML = '';
    allList.innerHTML = '';

    const sortedSubs = [...subscribedMap.entries()]
      .map(([id, sub]) => ({ id, sub, product: productMap.get(id) }))
      .filter(item => item.product)
      .sort((a, b) => {
        if (a.sub.paused && !b.sub.paused) return 1;
        if (!a.sub.paused && b.sub.paused) return -1;
        return a.product.name.localeCompare(b.product.name);
      });

    if (sortedSubs.length === 0) {
      const emptyLi = document.createElement('li');
      emptyLi.className = 'list-group-item text-center text-muted';
      emptyLi.textContent = 'Uh oh, your subscriptions list is empty 😢 Add products from the available list below.';
      subscribedList.appendChild(emptyLi);
    } else {
      for (const item of sortedSubs) {
        subscribedList.appendChild(
          createSubscribedItem(item.product, item.sub, item.sub.paused)
        );
      }
    }

    products.forEach(p => {
      if (!subscribedMap.has(p.id)) allList.appendChild(createAllProductItem(p));
    });
    if (window.lucide) window.lucide.createIcons();
    if (searchInput) {
      filterProducts(searchInput.value || '');
    }
  }

  async function subscribe(productId) {
    showGlobalLoader();
    try {
      const res = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId, paused: false })
      });
      subscribedMap.set(productId, res);
      render();
    } catch (err) {
      alert(err.message || 'Failed to subscribe');
    } finally {
      hideGlobalLoader();
    }
  }

  async function unsubscribe(productId) {
    showGlobalLoader();
    try {
      await fetchAPI('/api/subscriptions', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId })
      });
      subscribedMap.delete(productId);
      render();
    } catch (err) {
      alert(err.message || 'Failed to unsubscribe');
    } finally {
      hideGlobalLoader();
    }
  }

  async function pause(productId) {
    const li = subscribedList.querySelector(`li[data-product-id="${productId}"]`);
    const start = li ? li.querySelector('.sub-start').value : (subscribedMap.get(productId)?.start_time || '00:00');
    const end = li ? li.querySelector('.sub-end').value : (subscribedMap.get(productId)?.end_time || '23:59');
    showGlobalLoader();
    try {
      const res = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId, start_time: start, end_time: end, paused: true })
      });
      subscribedMap.set(productId, res);
      render();
    } catch (err) {
      alert(err.message || 'Failed to pause');
    } finally {
      hideGlobalLoader();
    }
  }

  async function resume(productId) {
    const li = subscribedList.querySelector(`li[data-product-id="${productId}"]`);
    const start = li ? li.querySelector('.sub-start').value : (subscribedMap.get(productId)?.start_time || '00:00');
    const end = li ? li.querySelector('.sub-end').value : (subscribedMap.get(productId)?.end_time || '23:59');
    showGlobalLoader();
    try {
      const res = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId, start_time: start, end_time: end, paused: false })
      });
      subscribedMap.set(productId, res);
      render();
    } catch (err) {
      alert(err.message || 'Failed to resume');
    } finally {
      hideGlobalLoader();
    }
  }

  async function updateTimes(productId, start, end) {
    showGlobalLoader();
    try {
      const res = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId, start_time: start, end_time: end, paused: !!subscribedMap.get(productId)?.paused })
      });
      subscribedMap.set(productId, res);
    } catch (err) {
      alert(err.message || 'Failed to update times');
    } finally {
      hideGlobalLoader();
    }
  }

  subscribedList.addEventListener('click', e => {
    const li = e.target.closest('li[data-product-id]');
    if (!li) return;
    if (e.target.closest('button')) e.preventDefault();
    if (e.target.closest('.unsub-btn')) {
      const id = li.dataset.productId;
      unsubscribe(id);
    } else if (e.target.closest('.pause-btn')) {
      const id = li.dataset.productId;
      const sub = subscribedMap.get(id);
      if (sub && sub.paused) {
        resume(id);
      } else {
        pause(id);
      }
    }
  });

  subscribedList.addEventListener('change', e => {
    if (!e.target.classList.contains('sub-start') && !e.target.classList.contains('sub-end')) return;
    const li = e.target.closest('li[data-product-id]');
    const start = li.querySelector('.sub-start').value;
    const end = li.querySelector('.sub-end').value;
    updateTimes(li.dataset.productId, start, end);
  });

  allList.addEventListener('click', e => {
    const btn = e.target.closest('.sub-btn');
    if (!btn) return;
    if (typeof e.preventDefault === 'function') {
      e.preventDefault();
    }
    const li = btn.closest('li[data-product-id]');
    subscribe(li.dataset.productId);
  });

  function filterProducts(term) {
    const items = allList.querySelectorAll('li');
    const searchWords = term.toLowerCase().split(' ').filter(word => word.length > 0);

    items.forEach(item => {
      const title = (item.dataset.name || item.querySelector('strong')?.textContent || '').toLowerCase();
      const matches = searchWords.every(word => title.includes(word));

      if (matches) {
        item.classList.remove('product-item-hidden');
      } else {
        item.classList.add('product-item-hidden');
      }
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', () => filterProducts(searchInput.value));
  }

  render();
  hideGlobalLoader();
  return recipient;
}

// Initialization is handled by the page that loads this component
