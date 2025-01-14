document.getElementById("login").addEventListener("click", () => {
    chrome.runtime.sendMessage({
        type: "checkLogin",
        data: { login: "exampleUser", password: "examplePass" }
    }, response => {
        document.getElementById("status").textContent = response.message;
    });
});
