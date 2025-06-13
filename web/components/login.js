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

  // User section elements
  const userEmailInput = document.getElementById('user-email'); // Reference to the actual input field
  const userEmailWrapper = document.getElementById('user-email-wrapper'); // Wrapper for email input + icon
  const userLoginBtn = document.getElementById('user-login-btn');
  const userErrorMessage = document.getElementById('user-error-message');
  const userContactAdminText = document.getElementById('user-contact-admin-btn'); // This is the <p> tag
  const userContactLinks = document.getElementById('user-contact-links');

  // REMOVE: Old user registration button declarations (userRegYesBtn, userRegNoBtn)
  // const userRegYesBtn = document.getElementById('user-reg-yes');
  // const userRegNoBtn = document.getElementById('user-reg-no');


  function showLoginPopup() {
    if (loginPopup) {
      loginPopup.style.display = 'flex';
    }
    if (adminSection) adminSection.style.display = 'block';
    if (userSection) userSection.style.display = 'none';

    if (adminRoleBtn) adminRoleBtn.classList.add('active');
    if (userRoleBtn) userRoleBtn.classList.remove('active');

    // Initial state for User Section when popup shows (though it's hidden by default)
    // This will also be reset when user tab is clicked
    if (userEmailInput) userEmailInput.value = '';
    if (userEmailWrapper) userEmailWrapper.style.display = 'flex'; // Make email input visible by default in user section
    if (userErrorMessage) userErrorMessage.style.display = 'none';
    if (userContactAdminText) userContactAdminText.style.display = 'none';
    if (userContactLinks) userContactLinks.style.display = 'none';
  }

  function showMainApp() {
    if (loginPopup) {
      loginPopup.style.display = 'none';
    }
    if (mainAppContent) {
      mainAppContent.style.display = 'block';
    }
  }

  if (adminRoleBtn) {
    adminRoleBtn.addEventListener('click', () => {
      if (adminSection) adminSection.style.display = 'block';
      if (userSection) userSection.style.display = 'none';
      adminRoleBtn.classList.add('active');
      if (userRoleBtn) userRoleBtn.classList.remove('active');
    });
  }

  if (userRoleBtn) {
    userRoleBtn.addEventListener('click', () => {
      if (adminSection) adminSection.style.display = 'none';
      if (userSection) userSection.style.display = 'block';
      userRoleBtn.classList.add('active');
      if (adminRoleBtn) adminRoleBtn.classList.remove('active');

      // Reset User Section to initial state when tab is clicked
      if (userEmailInput) userEmailInput.value = '';
      if (userEmailWrapper) userEmailWrapper.style.display = 'flex'; // Ensure email input is visible
      if (userErrorMessage) userErrorMessage.style.display = 'none';
      if (userContactAdminText) userContactAdminText.style.display = 'none';
      if (userContactLinks) userContactLinks.style.display = 'none';
    });
  }

  if (adminLoginBtn) {
    adminLoginBtn.addEventListener('click', () => {
      const email = adminEmailInput ? adminEmailInput.value.trim() : '';
      const password = adminPasswordInput ? adminPasswordInput.value.trim() : '';
      if (email && password) {
        showMainApp();
      } else {
        console.error('Admin login failed: Email and password are required.');
        // TODO: Display this error in the admin UI if an error field is added there
      }
    });
  }

  // New User Login Logic
  if (userLoginBtn) {
    userLoginBtn.addEventListener('click', () => {
      const email = userEmailInput ? userEmailInput.value.trim() : '';

      // Basic Validation
      if (email === '') {
        if (userErrorMessage) {
          userErrorMessage.textContent = 'Please enter your email.';
          userErrorMessage.style.display = 'block';
        }
        if (userContactAdminText) userContactAdminText.style.display = 'none';
        if (userContactLinks) userContactLinks.style.display = 'none';
        return;
      }

      // Placeholder Email Check
      if (email.toLowerCase() === 'test@example.com') {
        // This email is considered "not registered"
        if (userErrorMessage) {
          userErrorMessage.textContent = 'Email not registered.';
          userErrorMessage.style.display = 'block';
        }
        if (userContactAdminText) userContactAdminText.style.display = 'block'; // Show contact admin text
        if (userContactLinks) userContactLinks.style.display = 'block'; // Show contact links
      } else {
        // Any other email is considered "registered"
        if (userErrorMessage) userErrorMessage.style.display = 'none';
        if (userContactAdminText) userContactAdminText.style.display = 'none';
        if (userContactLinks) userContactLinks.style.display = 'none';
        showMainApp(); // Proceed to main application
      }
    });
  }

  // REMOVE: Old user registration event listeners
  // if (userRegYesBtn) { ... }
  // if (userRegNoBtn) { ... }

  showLoginPopup(); // Initialize and show the popup
}
