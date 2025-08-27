chrome.runtime.onInstalled.addListener(() => {
    console.log("Extensão instalada.");
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "checkLogin") {
        fetch("http://localhost:5000/api/check-login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request.data)
        })
        .then(response => response.json())
        .then(data => sendResponse(data))
        .catch(error => console.error("Erro na API:", error));
    }
    return true; // Manter a conexão assíncrona
});
