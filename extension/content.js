document.addEventListener("DOMContentLoaded", () => {
    const currentURL = window.location.href;
    chrome.runtime.sendMessage({
        type: "checkLogin",
        data: { url: currentURL }
    }, response => {
        console.log("Resposta do servidor:", response);
    });
});
