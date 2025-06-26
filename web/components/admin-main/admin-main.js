import '../status/status.js';
import {initPage} from '../ui/ui.js';
import {initParticles} from '../particles-config/particles-config.js';
import {initIcons} from '../icons/icons.js';
import {initRecipientsUI} from '../recipients-ui/recipients-ui.js';
import {initProductsUI} from '../products-ui/products-ui.js';
import '../subscription/subscriptions-ui.js';

document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('authToken');
  if (!token) {
    window.location.href = '../../index.html';
    return;
  }
  initParticles();
  initPage();
  initIcons();
  initRecipientsUI();
  initProductsUI();

  const switchUserBtn = document.getElementById('switch-user-btn');
  if (switchUserBtn) {
    switchUserBtn.addEventListener('click', () => {
      const email = localStorage.getItem('adminEmail');
      if (email) {
        localStorage.setItem('userEmail', email);
        localStorage.setItem('switchedFromAdmin', 'true');
        window.location.href = '../user-main/user.html';
      }
    });
  }

  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      localStorage.removeItem('authToken');
      localStorage.removeItem('adminEmail');
      localStorage.removeItem('userEmail');
      localStorage.removeItem('switchedFromAdmin');
      window.location.href = '../../index.html';
    });
  }

  // Email Blast Modal & Editor Initialization
  const emailBlastModalElement = document.getElementById('emailBlastModal');
  const emailBlastBtn = document.getElementById('email-blast-btn');
  let quillEditor;

  if (emailBlastModalElement && emailBlastBtn) {
    const emailBlastModal = new bootstrap.Modal(emailBlastModalElement);

    emailBlastBtn.addEventListener('click', () => {
      emailBlastModal.show();
    });

    // Initialize Quill editor
    // Doing it here to ensure it's ready when modal is shown,
    // but could also be done on modal 'shown.bs.modal' event if preferred.
    quillEditor = new Quill('#html-editor-container', {
      theme: 'snow', // 'snow' is a common theme with a toolbar
      modules: {
        toolbar: [
          [{ 'header': [1, 2, 3, false] }],
          ['bold', 'italic', 'underline', 'strike'],
          [{ 'list': 'ordered'}, { 'list': 'bullet' }],
          [{ 'color': [] }, { 'background': [] }],
          ['link'],
          ['clean']
        ]
      }
    });

    const sendEmailBlastBtn = document.getElementById('send-email-blast-btn');
    const emailBlastSubject = document.getElementById('email-blast-subject');
    const plainTextEditor = document.getElementById('plain-text-editor');
    const emailBlastStatus = document.getElementById('email-blast-status');
    const htmlEditorTab = document.getElementById('html-editor-tab');
    const recipientInput = document.getElementById('recipient-input');
    const recipientList = document.getElementById('recipient-list');
    let extraRecipients = [];
    let baseRecipients = [];

    const renderRecipients = () => {
      if (!recipientList) return;
      recipientList.innerHTML = '';
      const all = [...new Set([...baseRecipients, ...extraRecipients])];
      all.forEach(email => {
        const chip = document.createElement('span');
        chip.className = 'badge bg-secondary me-1 mb-1 d-flex align-items-center';

        const textSpan = document.createElement('span');
        textSpan.textContent = email;
        chip.appendChild(textSpan);

        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'btn-close btn-close-white btn-sm ms-1';
        closeBtn.addEventListener('click', () => {
          extraRecipients = extraRecipients.filter(e => e !== email);
          baseRecipients = baseRecipients.filter(e => e !== email);
          renderRecipients();
        });
        chip.appendChild(closeBtn);

        recipientList.appendChild(chip);
      });
    };

    const updateBaseRecipients = async () => {
      const rb = document.querySelector('input[name="recipientType"]:checked');
      const type = rb ? rb.value : 'self';
      const adminEmail = localStorage.getItem('adminEmail');
      if (type === 'self') {
        baseRecipients = adminEmail ? [adminEmail] : [];
        renderRecipients();
        return;
      }
      try {
        const recips = await window.fetchAPI('/api/recipients');
        if (type === 'all') {
          baseRecipients = recips.map(r => r.email);
        } else {
          const subs = await window.fetchAPI('/api/subscriptions');
          const subscribed = new Set();
          subs.forEach(s => {
            const paused = s.paused === true || s.paused === 'true';
            if (!paused) subscribed.add(s.recipient_id);
          });
          baseRecipients = recips.filter(r => !subscribed.has(r.id)).map(r => r.email);
        }
      } catch (err) {
        console.error('Error fetching recipients:', err);
        baseRecipients = [];
      }
      renderRecipients();
    };

    if (recipientInput && recipientList) {
      document.querySelectorAll('input[name="recipientType"]').forEach(r => {
        r.addEventListener('change', updateBaseRecipients);
      });
      updateBaseRecipients();

      recipientInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          const email = recipientInput.value.trim();
          if (email && /\S+@\S+\.\S+/.test(email)) {
            extraRecipients.push(email);
            renderRecipients();
            recipientInput.value = '';
          }
        }
      });
    }

    if (sendEmailBlastBtn && emailBlastSubject && plainTextEditor && emailBlastStatus && htmlEditorTab) {
      sendEmailBlastBtn.addEventListener('click', async () => {
        const subject = emailBlastSubject.value.trim();
        const recipientType = document.querySelector('input[name="recipientType"]:checked').value;

        let htmlBody = '';
        let plainBody = '';

        if (htmlEditorTab.classList.contains('active')) {
          htmlBody = quillEditor.root.innerHTML; // Get HTML content from Quill
          // A simple way to get plain text from Quill's HTML, or use quill.getText()
          // For now, let's assume if HTML is active, plainBody might be derived or empty if not explicitly provided.
          // For simplicity, if HTML is active, we'll primarily send HTML.
          // The API will need to handle if only one format is provided.
          plainBody = quillEditor.getText(); // Get plain text version from Quill
        } else {
          plainBody = plainTextEditor.value.trim();
          // If plain text is active, HTML body will be empty or derived by server if needed.
        }

        if (!subject) {
          emailBlastStatus.innerHTML = '<div class="alert alert-danger">Subject is required.</div>';
          return;
        }
        if (!htmlBody && !plainBody) {
          emailBlastStatus.innerHTML = '<div class="alert alert-danger">Email body cannot be empty.</div>';
          return;
        }

        emailBlastStatus.innerHTML = '<div class="alert alert-info">Sending emails...</div>';
        sendEmailBlastBtn.disabled = true;

        try {
          const token = localStorage.getItem('authToken');
          const response = await fetch('/api/email-blast', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
              subject,
              htmlBody,
              plainBody,
              recipientType,
              adminEmail: localStorage.getItem('adminEmail'), // For "self" recipient type
              extraRecipients
            })
          });

          const result = await response.json();

          if (response.ok) {
            emailBlastStatus.innerHTML = `<div class="alert alert-success">${result.message}</div>`;
            // Optionally close modal or clear form here
            // emailBlastSubject.value = '';
            // quillEditor.setText('');
            // plainTextEditor.value = '';
          } else {
            emailBlastStatus.innerHTML = `<div class="alert alert-danger">Error: ${result.message || 'Failed to send emails.'}</div>`;
          }
        } catch (error) {
          console.error('Error sending email blast:', error);
          emailBlastStatus.innerHTML = `<div class="alert alert-danger">An unexpected error occurred: ${error.message}</div>`;
        } finally {
          sendEmailBlastBtn.disabled = false;
        }
      });
    }
  }
});
