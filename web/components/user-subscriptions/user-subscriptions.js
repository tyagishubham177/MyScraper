import { fetchAPI, showGlobalLoader, hideGlobalLoader, sanitizeUrl } from '../utils/utils.js';

export async function initUserSubscriptionsUI() {
  showGlobalLoader();
  const email = localStorage.getItem('userEmail');
  if (!email) {
    window.location.href = '../../index.html';
    return;
  }

  let [recipients, products] = await Promise.all([
    fetchAPI('/api/recipients'),
    fetchAPI('/api/products')
  ]).catch(() => [null, null]);

  if (!recipients || !products) {
    console.error('Failed to load data');
    return;
  }

  const recipient = recipients.find(r => r.email === email);
  if (!recipient) {
    console.error('Recipient not found');
    return;
  }
  localStorage.setItem(`recipientId_${email}`, recipient.id);
  if (recipient.pincode) {
    localStorage.setItem(`pincode_${email}`, recipient.pincode);
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

  document.querySelectorAll('.panel-toggle[data-collapsible-target]').forEach(btn => {
    collapseToggleMap.set(btn.dataset.collapsibleTarget, btn);
  });

  function updateCollapseMode() {
    if (typeof bootstrap === 'undefined' || !bootstrap.Collapse) return;
    const isMobile = window.innerWidth < 1200;

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

  window.addEventListener('resize', updateCollapseMode);
  updateCollapseMode();

  function createSubscribedItem(product, sub, paused = false) {
    const li = document.createElement('li');
    li.className = 'list-group-item product-list-item-mobile' + (paused ? ' paused' : '');
    li.dataset.productId = product.id;
    li.dataset.name = product.name.toLowerCase();

    const details = document.createElement('div');
    details.className = 'product-details mb-2';
    const headingRow = document.createElement('div');
    headingRow.className = 'product-heading-row';
    const nameEl = document.createElement('h5');
    nameEl.className = 'product-name mb-0';
    nameEl.textContent = product.name;
    const statusPill = document.createElement('span');
    statusPill.className = 'subscription-status ' + (paused ? 'is-paused' : 'is-active');
    statusPill.textContent = paused ? 'Paused' : 'Active';
    const linkEl = document.createElement('a');
    const safeUrl = sanitizeUrl(product.url);
    linkEl.href = safeUrl || '#';
    linkEl.target = '_blank';
    linkEl.className = 'product-url d-block small';
    linkEl.title = product.url;
    const displayUrl = product.url.length > 30 ? product.url.substring(0, 27) + '...' : product.url;
    linkEl.textContent = `${displayUrl} `;
    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', 'external-link');
    icon.className = 'lucide-xs';
    linkEl.appendChild(icon);
    headingRow.appendChild(nameEl);
    headingRow.appendChild(statusPill);
    details.appendChild(headingRow);
    details.appendChild(linkEl);

    const controls = document.createElement('div');
    controls.className = 'product-controls d-flex align-items-center';
    controls.innerHTML = `
      <div class="time-slot-group me-1">
        <input type="time" class="form-control form-control-sm sub-start" value="${sub.start_time || '00:00'}">
      </div>
      <div class="time-slot-group me-2">
        <input type="time" class="form-control form-control-sm sub-end" value="${sub.end_time || '23:59'}">
      </div>
      <div class="control-actions">
        <button class="btn btn-sm btn-outline-secondary pause-btn btn-icon"><i data-lucide="${paused ? 'play' : 'pause'}"></i></button>
        <button class="btn btn-sm btn-outline-danger unsub-btn btn-icon"><i data-lucide="x"></i></button>
      </div>`;

    li.appendChild(details);
    li.appendChild(controls);
    return li;
  }

  function createAllProductItem(product) {
    const li = document.createElement('li');
    li.className = 'list-group-item d-flex justify-content-between align-items-center';
    li.dataset.productId = product.id;
    li.dataset.name = product.name.toLowerCase();

    const info = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = product.name;
    const link = document.createElement('small');
    link.className = 'd-block text-muted';
    const displayUrl = product.url.length > 30 ? product.url.substring(0, 27) + '...' : product.url;
    const anchor = document.createElement('a');
    const safeUrl = sanitizeUrl(product.url);
    anchor.href = safeUrl || '#';
    anchor.target = '_blank';
    anchor.title = product.url;
    anchor.textContent = `${displayUrl} `;
    const icon2 = document.createElement('i');
    icon2.setAttribute('data-lucide', 'external-link');
    icon2.className = 'lucide-small';
    anchor.appendChild(icon2);
    link.appendChild(anchor);
    info.appendChild(strong);
    info.appendChild(link);

    const btn = document.createElement('button');
    btn.className = 'btn btn-sm btn-outline-primary sub-btn';
    btn.innerHTML = '<i data-lucide="plus"></i>';

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
