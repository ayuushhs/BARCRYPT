// Function to generate a strong password using our backend
async function generateStrongPassword() {
    try {
        const response = await fetch('http://localhost:5000/api/generate-password', {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Accept': 'application/json'
            }
        });

        const data = await response.json();
        if (data.success && data.password) {
            return {
                password: data.password,
                analysis: data.analysis
            };
        } else {
            throw new Error(data.message || 'Failed to generate password');
        }
    } catch (error) {
        console.error('Error generating password:', error);
        // Fallback to basic generation if backend fails
        return generateBasicPassword();
    }
}

// Fallback password generation function
function generateBasicPassword() {
    const length = 16;
    const charset = {
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        numbers: '0123456789',
        symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
    };
    
    let password = '';
    
    // Ensure at least one character from each set
    password += charset.uppercase[Math.floor(Math.random() * charset.uppercase.length)];
    password += charset.lowercase[Math.floor(Math.random() * charset.lowercase.length)];
    password += charset.numbers[Math.floor(Math.random() * charset.numbers.length)];
    password += charset.symbols[Math.floor(Math.random() * charset.symbols.length)];
    
    // Fill the rest randomly
    const allChars = Object.values(charset).join('');
    for (let i = password.length; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }
    
    // Shuffle the password
    return {
        password: password.split('').sort(() => Math.random() - 0.5).join(''),
        analysis: null
    };
}

// Function to detect login forms using various methods
function detectLoginForm() {
    // Common selectors for login forms
    const formSelectors = [
        // Standard login forms
        'form[action*="login"]',
        'form[action*="signin"]',
        'form[action*="auth"]',
        'form[id*="login"]',
        'form[id*="signin"]',
        'form[class*="login"]',
        'form[class*="signin"]',
        // Social media specific selectors
        '#loginForm',
        '#login_form',
        '#login-form',
        '#auth-form',
        // Generic password form detection
        'form:has(input[type="password"])',
        // Divs that might contain login forms
        'div[class*="login"]',
        'div[class*="signin"]',
        'div[id*="login"]',
        'div[id*="signin"]'
    ];

    // First try: Look for password fields directly
    const passwordFields = document.querySelectorAll('input[type="password"]');
    for (const passwordField of passwordFields) {
        // Look for username field in nearby containers
        const possibleContainers = [
            passwordField.closest('form'),
            passwordField.closest('div[class*="login"]'),
            passwordField.closest('div[class*="signin"]'),
            passwordField.closest('div[role="main"]'),
            passwordField.closest('main'),
            passwordField.parentElement?.closest('div')
        ];

        for (const container of possibleContainers) {
            if (container) {
                const usernameField = findUsernameField(container);
                if (usernameField) {
                    console.log('Found login form via password field:', container);
                    return {
                        form: container,
                        usernameField,
                        passwordField,
                        website: window.location.hostname
                    };
                }
            }
        }
    }

    // Second try: Look for forms using selectors
    for (const selector of formSelectors) {
        try {
            const elements = document.querySelectorAll(selector);
            for (const element of elements) {
                const result = analyzeForm(element);
                if (result) {
                    console.log('Found login form via selector:', selector);
                    return result;
                }
            }
        } catch (e) {
            console.log('Error with selector:', selector, e);
        }
    }

    // Final try: Look for any form with a password field
    const allForms = document.getElementsByTagName('form');
    for (const form of allForms) {
        const result = analyzeForm(form);
        if (result) {
            console.log('Found login form via form scan');
            return result;
        }
    }

    return null;
}

// Helper function to analyze a form or container
function analyzeForm(container) {
    const inputs = container.querySelectorAll('input');
    let passwordField = null;
    let usernameField = null;

    for (const input of inputs) {
        // Check for password field
        if (input.type === 'password') {
            passwordField = input;
        }
        // Check for username/email field
        else if (isUsernameField(input)) {
            usernameField = input;
        }
    }

    if (passwordField && usernameField) {
        return {
            form: container,
            usernameField,
            passwordField,
            website: window.location.hostname
        };
    }

    return null;
}

// Helper function to identify username fields
function isUsernameField(input) {
    // Common username/email field identifiers
    const usernameIdentifiers = [
        'user', 'email', 'login', 'id', 'account', 'name', 'username',
        'phone', 'mobile', 'tel', 'identifier'
    ];
    
    // Check input type
    if (input.type === 'email' || input.type === 'text' || input.type === 'tel') {
        // Check various attributes
        const attributes = [
            input.id?.toLowerCase(),
            input.name?.toLowerCase(),
            input.className?.toLowerCase(),
            input.placeholder?.toLowerCase(),
            input.getAttribute('aria-label')?.toLowerCase()
        ];

        // Check if any attribute matches our identifiers
        return attributes.some(attr => 
            attr && (
                usernameIdentifiers.some(id => attr.includes(id)) ||
                attr.includes('user') ||
                attr.includes('email')
            )
        );
    }

    return false;
}

// Helper function to find username field in a container
function findUsernameField(container) {
    const inputs = container.querySelectorAll('input');
    for (const input of inputs) {
        if (isUsernameField(input)) {
            return input;
        }
    }
    return null;
}

// Function to check password strength
function checkPasswordStrength(password) {
    let score = 0;
    
    // Length check
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    
    // Character variety checks
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    
    if (score < 3) return 'weak';
    if (score < 5) return 'medium';
    return 'strong';
}

// Function to create and show the password suggestion popup
function showPasswordSuggestion(loginForm) {
    // Remove any existing popups
    const existingPopup = document.querySelector('.barcrypt-popup');
    if (existingPopup) {
        existingPopup.remove();
    }

    const popup = document.createElement('div');
    popup.className = 'barcrypt-popup';
    
    const strength = checkPasswordStrength(loginForm.passwordField.value);
    
    popup.innerHTML = `
        <div class="barcrypt-popup-content">
            <button class="close-button" title="Close">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M18 6L6 18M6 6l12 12"/>
                </svg>
            </button>
            
            <div class="barcrypt-popup-header">
                <img src="${chrome.runtime.getURL('icons/icon48.png')}" alt="BarcCrypt">
                <h3>Save password in BarcCrypt?</h3>
            </div>

            <div class="password-section">
                <label class="password-label">Password for ${window.location.hostname}</label>
                <div class="password-preview">
                    <input type="text" value="${loginForm.passwordField.value}" readonly>
                    <button class="copy-btn" title="Copy password">
                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor">
                            <path d="M13 4H5C4.44772 4 4 4.44772 4 5V13C4 13.5523 4.44772 14 5 14H13C13.5523 14 14 13.5523 14 13V5C14 4.44772 13.5523 4 13 4Z"/>
                            <path d="M11 2H3C2.44772 2 2 2.44772 2 3V11"/>
                        </svg>
                    </button>
                </div>
                
                <div class="password-strength">
                    <span>Strength:</span>
                    <div class="strength-indicator strength-${strength}">
                        <div></div>
                    </div>
                    <span>${strength.charAt(0).toUpperCase() + strength.slice(1)}</span>
                </div>
            </div>

            <div class="actions">
                <button class="generate-btn">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor">
                        <path d="M13 8H3M3 8L6 5M3 8L6 11"/>
                    </svg>
                    Generate New
                </button>
                <button class="save-btn">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor">
                        <path d="M3 8.5L6 11.5L13 4.5"/>
                    </svg>
                    Save
                </button>
            </div>
        </div>
    `;

    document.body.appendChild(popup);

    // Add event listeners
    popup.querySelector('.close-button').addEventListener('click', () => {
        popup.remove();
    });

    popup.querySelector('.copy-btn').addEventListener('click', () => {
        const passwordText = loginForm.passwordField.value;
        navigator.clipboard.writeText(passwordText).then(() => {
            const copyBtn = popup.querySelector('.copy-btn');
            copyBtn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor">
                    <path d="M3 8L6 11L13 4" stroke-width="2"/>
                </svg>
            `;
            setTimeout(() => {
                copyBtn.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor">
                        <path d="M13 4H5C4.44772 4 4 4.44772 4 5V13C4 13.5523 4.44772 14 5 14H13C13.5523 14 14 13.5523 14 13V5C14 4.44772 13.5523 4 13 4Z"/>
                        <path d="M11 2H3C2.44772 2 2 2.44772 2 3V11"/>
                    </svg>
                `;
            }, 2000);
        });
    });

    popup.querySelector('.generate-btn').addEventListener('click', async () => {
        const result = await generateStrongPassword();
        const newPassword = result.password;
        
        loginForm.passwordField.value = newPassword;
        popup.querySelector('.password-preview input').value = newPassword;
        
        // Update strength indicator using the analysis if available
        let strength;
        if (result.analysis) {
            const crackTime = result.analysis.crack_times.offline_slow;
            if (crackTime > 31536000 * 100) { // More than 100 years
                strength = 'strong';
            } else if (crackTime > 31536000) { // More than 1 year
                strength = 'medium';
            } else {
                strength = 'weak';
            }
        } else {
            strength = checkPasswordStrength(newPassword);
        }
        
        const strengthIndicator = popup.querySelector('.strength-indicator');
        strengthIndicator.className = `strength-indicator strength-${strength}`;
        popup.querySelector('.password-strength span:last-child').textContent = 
            strength.charAt(0).toUpperCase() + strength.slice(1);
        
        // Trigger input event to update any password field listeners
        loginForm.passwordField.dispatchEvent(new Event('input', { bubbles: true }));
    });

    popup.querySelector('.save-btn').addEventListener('click', async () => {
        try {
            // Check login status first
            const isLoggedIn = await checkLoginStatus();
            console.log('Is logged in:', isLoggedIn);  // Debug log
            
            if (!isLoggedIn) {
                showLoginPrompt();
                return;
            }

            const response = await fetch('http://localhost:5000/api/passwords', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    website: window.location.href,
                    username: loginForm.usernameField.value,
                    password: loginForm.passwordField.value
                }),
                credentials: 'include'
            });

            const data = await response.json();
            
            if (response.ok && data.success) {
                popup.querySelector('.barcrypt-popup-content').innerHTML = `
                    <div class="barcrypt-popup-header">
                        <img src="${chrome.runtime.getURL('icons/icon48.png')}" alt="BarcCrypt">
                        <h3>Password Saved</h3>
                    </div>
                    <div class="success-message">
                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor">
                            <path d="M3 8L6 11L13 4" stroke-width="2"/>
                        </svg>
                        Password has been securely saved
                    </div>
                `;
                setTimeout(() => {
                    popup.remove();
                }, 2000);
            } else {
                throw new Error(data.message || 'Failed to save password');
            }
        } catch (error) {
            console.error('Error saving password:', error);
            popup.querySelector('.barcrypt-popup-content').innerHTML = `
                <div class="barcrypt-popup-header">
                    <img src="${chrome.runtime.getURL('icons/icon48.png')}" alt="BarcCrypt">
                    <h3>Error</h3>
                </div>
                <div class="error-message">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor">
                        <path d="M8 5v4M8 11v.01M3 3l10 10M13 3L3 13"/>
                    </svg>
                    ${error.message || 'Failed to save password. Please ensure you\'re logged in.'}
                </div>
            `;
        }
    });
}

// Function to auto-fill saved passwords
async function autoFillPassword(loginForm) {
    try {
        const response = await fetch(`http://localhost:5000/api/passwords/search?website=${encodeURIComponent(window.location.hostname)}&username=${encodeURIComponent(loginForm.usernameField.value)}`, {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.password) {
                loginForm.passwordField.value = data.password;
                loginForm.passwordField.dispatchEvent(new Event('input', { bubbles: true }));
            }
        }
    } catch (error) {
        console.error('Error auto-filling password:', error);
    }
}

// Main function to initialize the extension
function initialize() {
    console.log('BarcCrypt: Initializing...');
    
    // Try to detect login form
    let loginForm = detectLoginForm();
    
    // If no form found initially, retry after a short delay for dynamic pages
    if (!loginForm) {
        setTimeout(() => {
            loginForm = detectLoginForm();
            if (loginForm) {
                console.log('BarcCrypt: Found login form after delay');
                setupFormHandlers(loginForm);
            }
        }, 1000);
    } else {
        console.log('BarcCrypt: Found login form immediately');
        setupFormHandlers(loginForm);
    }

    // Watch for dynamic form additions
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            if (mutation.addedNodes.length) {
                const loginForm = detectLoginForm();
                if (loginForm) {
                    console.log('BarcCrypt: Detected dynamically added login form');
                    setupFormHandlers(loginForm);
                    break;
                }
            }
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

// Setup event handlers for the login form
function setupFormHandlers(loginForm) {
    if (!loginForm) return;

    // Remove any existing handlers
    loginForm.usernameField.removeEventListener('change', handleUsernameChange);
    loginForm.passwordField.removeEventListener('input', handlePasswordInput);
    if (loginForm.form.tagName === 'FORM') {
        loginForm.form.removeEventListener('submit', handleFormSubmit);
    }

    // Add username change handler
    loginForm.usernameField.addEventListener('change', handleUsernameChange);
    
    // Add password input handler
    loginForm.passwordField.addEventListener('input', handlePasswordInput);
    
    // Add form submit handler
    if (loginForm.form.tagName === 'FORM') {
        loginForm.form.addEventListener('submit', handleFormSubmit);
    }

    // Store the login form reference
    window._barcryptLoginForm = loginForm;
}

// Event handler for username changes
function handleUsernameChange(event) {
    const loginForm = window._barcryptLoginForm;
    if (loginForm) {
        autoFillPassword(loginForm);
    }
}

// Event handler for password input
function handlePasswordInput(event) {
    const loginForm = window._barcryptLoginForm;
    if (loginForm && loginForm.passwordField.value && !document.querySelector('.barcrypt-popup')) {
        showPasswordSuggestion(loginForm);
    }
}

// Event handler for form submission
function handleFormSubmit(event) {
    const loginForm = window._barcryptLoginForm;
    if (loginForm) {
        // Show password save popup after successful login
        setTimeout(() => {
            if (loginForm.passwordField.value) {
                showPasswordSuggestion(loginForm);
            }
        }, 500);
    }
}

// Initialize when the page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkLoginForm') {
        const loginForm = detectLoginForm();
        if (loginForm && loginForm.passwordField.value) {
            showPasswordSuggestion(loginForm);
        }
    }
});

// Function to check login status
async function checkLoginStatus() {
    try {
        const response = await fetch('http://localhost:5000/api/check-login', {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Accept': 'application/json'
            }
        });

        const data = await response.json();
        console.log('Login check response:', data);  // Debug log
        
        if (data.success) {
            return data.logged_in;
        }
        return false;
    } catch (error) {
        console.error('Error checking login status:', error);
        return false;
    }
}

// Function to show login prompt
function showLoginPrompt() {
    const popup = document.createElement('div');
    popup.className = 'barcrypt-popup';
    
    popup.innerHTML = `
        <div class="barcrypt-popup-content">
            <div class="barcrypt-popup-header">
                <img src="${chrome.runtime.getURL('icons/icon48.png')}" alt="BarcCrypt">
                <h3>Login Required</h3>
            </div>
            <div class="error-message">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor">
                    <path d="M8 5v4M8 11v.01M3 3l10 10M13 3L3 13"/>
                </svg>
                Please log in to BarcCrypt to save passwords
            </div>
            <div class="actions" style="margin-top: 16px;">
                <button class="login-btn" onclick="window.open('http://localhost:5000/login', '_blank')">
                    Login to BarcCrypt
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(popup);

    // Add close button
    const closeButton = document.createElement('button');
    closeButton.className = 'close-button';
    closeButton.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M18 6L6 18M6 6l12 12"/>
        </svg>
    `;
    popup.querySelector('.barcrypt-popup-content').appendChild(closeButton);

    // Add event listeners
    closeButton.addEventListener('click', () => popup.remove());
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (document.body.contains(popup)) {
            popup.remove();
        }
    }, 5000);
} 