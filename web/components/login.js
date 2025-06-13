export function initLogin() {
  const loginPopup = document.getElementById('login-popup');
  const mainAppContent = document.getElementById('main-app-content');

  const adminRoleBtn = document.getElementById('admin-role-btn');
  const userRoleBtn = document.getElementById('user-role-btn');

  const adminSection = document.getElementById('admin-section');
  const userSection = document.getElementById('user-section');

  const adminEmailInput = document.getElementById('admin-email');
  const adminPasswordInput = document.getElementById('admin-password');
  const adminLoginBtn = document.getElementById('admin-login-btn');

  const userRegYesBtn = document.getElementById('user-reg-yes');
  const userRegNoBtn = document.getElementById('user-reg-no');
  const userEmailInput = document.getElementById('user-email');
  const userContactAdminBtn = document.getElementById('user-contact-admin-btn');
  const userContactLinks = document.getElementById('user-contact-links');

  // Function to show the login popup
  function showLoginPopup() {
    if (loginPopup) {
      loginPopup.style.display = 'block';
    }
    // Initially, show admin section and hide user section
    if (adminSection) adminSection.style.display = 'block';
    if (userSection) userSection.style.display = 'none';
    // Ensure user sub-elements are hidden initially
    if (userEmailInput) userEmailInput.style.display = 'none';
    if (userContactAdminBtn) userContactAdminBtn.style.display = 'none';
    if (userContactLinks) userContactLinks.style.display = 'none';
  }

  // Function to show the main application
  function showMainApp() {
    if (loginPopup) {
      loginPopup.style.display = 'none';
    }
    if (mainAppContent) {
      mainAppContent.style.display = 'block';
    }
  }

  // Event Listeners for Role Selector
  if (adminRoleBtn) {
    adminRoleBtn.addEventListener('click', () => {
      if (adminSection) adminSection.style.display = 'block';
      if (userSection) userSection.style.display = 'none';
      // Optional: Add active class styling if needed
      adminRoleBtn.classList.add('active'); // Placeholder for active state
      if (userRoleBtn) userRoleBtn.classList.remove('active');
    });
  }

  if (userRoleBtn) {
    userRoleBtn.addEventListener('click', () => {
      if (adminSection) adminSection.style.display = 'none';
      if (userSection) userSection.style.display = 'block';
      // Optional: Add active class styling if needed
      userRoleBtn.classList.add('active'); // Placeholder for active state
      if (adminRoleBtn) adminRoleBtn.classList.remove('active');
      // Reset user section sub-elements visibility
      if (userEmailInput) userEmailInput.style.display = 'none';
      if (userContactAdminBtn) userContactAdminBtn.style.display = 'none';
      if (userContactLinks) userContactLinks.style.display = 'none';
    });
  }

  // Admin Login Logic
  if (adminLoginBtn) {
    adminLoginBtn.addEventListener('click', () => {
      const email = adminEmailInput ? adminEmailInput.value : '';
      const password = adminPasswordInput ? adminPasswordInput.value : '';

      // Placeholder authentication
      if (email && password) {
        showMainApp();
      } else {
        // Optional: Show error message
        console.error('Admin login failed: Email and password are required.');
        // You might want to display this error to the user in the UI
      }
    });
  }

  // User Section Logic
  if (userRegYesBtn) {
    userRegYesBtn.addEventListener('click', () => {
      if (userEmailInput) userEmailInput.style.display = 'block';
      if (userContactAdminBtn) userContactAdminBtn.style.display = 'none';
      if (userContactLinks) userContactLinks.style.display = 'none';
    });
  }

  if (userRegNoBtn) {
    userRegNoBtn.addEventListener('click', () => {
      if (userEmailInput) userEmailInput.style.display = 'none';
      if (userContactAdminBtn) userContactAdminBtn.style.display = 'block';
      if (userContactLinks) userContactLinks.style.display = 'block';
    });
  }

  // Show the login popup when initLogin is called
  showLoginPopup();
}
