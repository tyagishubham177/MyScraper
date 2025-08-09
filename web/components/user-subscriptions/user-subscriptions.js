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

  function createSubscribedItem(product, sub, paused = false) {
    const card = document.createElement('div');
    card.className = 'product-card' + (paused ? ' paused' : '');
    card.dataset.productId = product.id;
    card.dataset.name = product.name.toLowerCase();

    const safeUrl = sanitizeUrl(product.url) || '#';

    card.innerHTML = `
      <h5 class="product-name">
        <a href="${safeUrl}" target="_blank" title="${product.url}">${product.name}</a>
      </h5>
      <div class="product-controls">
        <div class="time-slot-group me-auto">
          <input type="time" class="form-control form-control-sm sub-start" value="${sub.start_time || '00:00'}" title="Notification start time">
          <input type="time" class="form-control form-control-sm sub-end" value="${sub.end_time || '23:59'}" title="Notification end time">
        </div>
        <button class="btn btn-sm btn-outline-secondary pause-btn" title="${paused ? 'Resume' : 'Pause'}">
          <i data-lucide="${paused ? 'play' : 'pause'}"></i>
        </button>
        <button class="btn btn-sm btn-outline-danger unsub-btn" title="Unsubscribe">
          <i data-lucide="x"></i>
        </button>
      </div>
    `;
    return card;
  }

  function createAllProductItem(product) {
    const card = document.createElement('div');
    card.className = 'product-card';
    card.dataset.productId = product.id;
    card.dataset.name = product.name.toLowerCase();

    const safeUrl = sanitizeUrl(product.url) || '#';

    card.innerHTML = `
      <h5 class="product-name">
        <a href="${safeUrl}" target="_blank" title="${product.url}">${product.name}</a>
      </h5>
      <div class="product-controls">
        <button class="btn btn-sm btn-primary sub-btn" title="Subscribe">
          <i data-lucide="plus"></i> Subscribe
        </button>
      </div>
    `;
    return card;
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
      subscribedList.innerHTML = '<p class="text-muted text-center w-100">Your subscriptions list is empty. Add products from the available list.</p>';
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

    if (allList.children.length === 0) {
        allList.innerHTML = '<p class="text-muted text-center w-100">All available products are subscribed.</p>';
    }

    if (window.lucide) window.lucide.createIcons();
    filterProducts(searchInput.value || '');
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

  async function updateSubscription(productId, updates) {
    showGlobalLoader();
    try {
        const currentSub = subscribedMap.get(productId) || {};
        const body = {
            recipient_id: recipient.id,
            product_id: productId,
            start_time: updates.start_time ?? currentSub.start_time ?? '00:00',
            end_time: updates.end_time ?? currentSub.end_time ?? '23:59',
            paused: updates.paused ?? currentSub.paused ?? false,
        };
      const res = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      subscribedMap.set(productId, res);
      render();
    } catch (err) {
      alert(err.message || 'Failed to update subscription');
    } finally {
      hideGlobalLoader();
    }
  }

  subscribedList.addEventListener('click', e => {
    const card = e.target.closest('.product-card[data-product-id]');
    if (!card) return;

    const id = card.dataset.productId;
    if (e.target.closest('.unsub-btn')) {
      unsubscribe(id);
    } else if (e.target.closest('.pause-btn')) {
      const sub = subscribedMap.get(id);
      updateSubscription(id, { paused: !sub.paused });
    }
  });

  subscribedList.addEventListener('change', e => {
    if (!e.target.classList.contains('sub-start') && !e.target.classList.contains('sub-end')) return;
    const card = e.target.closest('.product-card[data-product-id]');
    const start = card.querySelector('.sub-start').value;
    const end = card.querySelector('.sub-end').value;
    updateSubscription(card.dataset.productId, { start_time: start, end_time: end });
  });

  allList.addEventListener('click', e => {
    const btn = e.target.closest('.sub-btn');
    if (!btn) return;
    const card = btn.closest('.product-card[data-product-id]');
    subscribe(card.dataset.productId);
  });

  function filterProducts(term) {
    const searchWords = term.toLowerCase().split(' ').filter(Boolean);

    document.querySelectorAll('#all-products-list .product-card').forEach(card => {
        const name = card.dataset.name || '';
        const isVisible = searchWords.every(word => name.includes(word));
        card.style.display = isVisible ? '' : 'none';
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', () => filterProducts(searchInput.value));
  }

  render();
  hideGlobalLoader();
  return recipient;
}
