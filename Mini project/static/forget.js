// Switch to the Forgot Password Form
function showForgotPasswordForm() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('forgot-password-form').style.display = 'block';
}

// Switch back to the Login Form
function showLoginForm() {
    document.getElementById('forgot-password-form').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
}

// Handle Forgot Password Form Submission
document.getElementById('forgotPasswordForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const email = document.getElementById('email').value;

    // Send email data to the backend
    const response = await fetch('http://127.0.0.1:5000/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
    });

    const result = await response.json();
    alert(result.message);
});