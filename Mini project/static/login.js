// Switch to Forgot Password Form
function showForgotPasswordForm() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('forgot-password-form').style.display = 'block';
    document.getElementById('register-form').style.display = 'none';
}

// Switch to Registration Form
function showRegisterForm() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('forgot-password-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
}

// Switch to Login Form
function showLoginForm() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('forgot-password-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'none';
}

// Handle Registration Form Submission
document.getElementById('registerForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const username = document.getElementById('new-username').value;
    const email = document.getElementById('new-email').value;
    const password = document.getElementById('new-password').value;

    // Send data to backend
    const response = await fetch('http://127.0.0.1:5000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
    });

    const result = await response.json();
    alert(result.message);

    if (response.ok) {
        // Redirect to login form on successful registration
        showLoginForm();
    }
});