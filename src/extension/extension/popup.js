document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const logoutBtn = document.getElementById('logoutBtn');
    const goToSiteBtn = document.getElementById('goToSiteBtn');
    const mainTabs = document.querySelectorAll('#mainTabs .tab');

    // Mock login
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        document.getElementById('login-page').classList.remove('active');
        document.getElementById('passwords-page').classList.add('active');
    });

    // Logout
    logoutBtn.addEventListener('click', () => {
        document.getElementById('passwords-page').classList.remove('active');
        document.getElementById('login-page').classList.add('active');
    });

    // Go to website
    goToSiteBtn.addEventListener('click', () => {
        // Replace with your actual website URL
        chrome.tabs.create({ url: 'https://your-website.com' });
    });

    // Tab navigation
    mainTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.tab;

            // Update active tab
            mainTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Update content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(tabName).classList.add('active');
        });
    });
});