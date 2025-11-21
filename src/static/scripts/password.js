function togglePassword(inputId, iconId) {
    const passwordField = document.getElementById(inputId);
    const toggleIcon = document.getElementById(iconId);
    
    if (passwordField.type === 'password') {
        passwordField.type = 'text';
        toggleIcon.innerHTML = `
            <i class="bi bi-eye-slash"></i>
        `;
    } else {
        passwordField.type = 'password';
        toggleIcon.innerHTML = `
            <i class="icon bi bi-eye"></i>
        `;
    }
}