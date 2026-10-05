const API_URL = "http://127.0.0.1:8000";

const messageTab = document.getElementById("messageTab");
const urlTab = document.getElementById("urlTab");

const messageInputContainer = document.getElementById(
    "messageInputContainer"
);

const urlInputContainer = document.getElementById(
    "urlInputContainer"
);

const messageInput = document.getElementById("messageInput");
const urlInput = document.getElementById("urlInput");

const analyzeButton = document.getElementById("analyzeButton");
const resultContainer = document.getElementById("result");
const statusMessage = document.getElementById("status");

let currentMode = "message";


messageTab.addEventListener("click", () => {
    switchMode("message");
});


urlTab.addEventListener("click", () => {
    switchMode("url");
});


analyzeButton.addEventListener("click", analyzeInput);


function switchMode(mode) {
    currentMode = mode;

    resultContainer.innerHTML = "";
    statusMessage.textContent = "";

    if (mode === "message") {
        messageTab.classList.add("active");
        urlTab.classList.remove("active");

        messageInputContainer.classList.remove("hidden");
        urlInputContainer.classList.add("hidden");

        analyzeButton.textContent = "Analyze Message";
    } else {
        urlTab.classList.add("active");
        messageTab.classList.remove("active");

        urlInputContainer.classList.remove("hidden");
        messageInputContainer.classList.add("hidden");

        analyzeButton.textContent = "Analyze URL";
    }
}


async function analyzeInput() {
    if (currentMode === "message") {
        await analyzeMessage();
    } else {
        await analyzeURL();
    }
}


async function analyzeMessage() {
    const message = messageInput.value.trim();

    if (!message) {
        showStatus("Please enter a message to analyze.");
        return;
    }

    setLoading(true);
    showStatus("Analyzing message...");

    try {
        const response = await fetch(
            `${API_URL}/api/analyze/message`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    message: message,
                }),
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail || "Unable to analyze the message."
            );
        }

        displayMessageResult(data);
        showStatus("Analysis complete.");

    } catch (error) {
        showStatus(`Error: ${error.message}`);
        resultContainer.innerHTML = "";
    } finally {
        setLoading(false);
    }
}


async function analyzeURL() {
    const url = urlInput.value.trim();

    if (!url) {
        showStatus("Please enter a URL to analyze.");
        return;
    }

    setLoading(true);
    showStatus("Analyzing URL...");

    try {
        const response = await fetch(
            `${API_URL}/api/analyze/url`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    url: url,
                }),
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail || "Unable to analyze the URL."
            );
        }

        displayURLResult(data);
        showStatus("Analysis complete.");

    } catch (error) {
        showStatus(`Error: ${error.message}`);
        resultContainer.innerHTML = "";
    } finally {
        setLoading(false);
    }
}


function displayMessageResult(data) {
    const indicators = data.indicators.length
        ? data.indicators
            .map(
                indicator =>
                    `<li>${escapeHtml(indicator)}</li>`
            )
            .join("")
        : "<li>No suspicious indicators detected.</li>";

    const urls = data.urls.length
        ? data.urls
            .map(
                url =>
                    `<li>${escapeHtml(url)}</li>`
            )
            .join("")
        : "<li>No URLs detected.</li>";

    const recommendations = data.recommended_actions.length
        ? data.recommended_actions
            .map(
                action =>
                    `<li>${escapeHtml(action)}</li>`
            )
            .join("")
        : "<li>No immediate security action identified.</li>";

    const aiExplanation = data.ai_explanation
        ? `
            <div class="ai-explanation">
                <h3>🤖 AI Explanation</h3>
                <p>${formatAIExplanation(data.ai_explanation)}</p>
            </div>
        `
        : "";

    resultContainer.innerHTML = `
        <div class="result-card">

            <h2>Message Analysis</h2>

            <p>
                <strong>Risk:</strong>
                <span class="risk-${data.risk.toLowerCase()}">
                    ${escapeHtml(data.risk)}
                </span>
            </p>

            <p>
                <strong>Risk Score:</strong>
                ${data.score}/100
            </p>

            <p>
                <strong>Possible Attack:</strong>
                ${escapeHtml(data.possible_attack)}
            </p>

            <h3>Detected Indicators</h3>

            <ul>
                ${indicators}
            </ul>

            <h3>Detected URLs</h3>

            <ul>
                ${urls}
            </ul>

            <h3>Recommended Actions</h3>

            <ul>
                ${recommendations}
            </ul>

            ${aiExplanation}

            ${disclaimer()}
        </div>
    `;
}


function displayURLResult(data) {
    const indicators = data.indicators.length
        ? data.indicators
            .map(
                indicator =>
                    `<li>${escapeHtml(indicator)}</li>`
            )
            .join("")
        : "<li>No suspicious indicators detected.</li>";

    const aiExplanation = data.ai_explanation
        ? `
            <div class="ai-explanation">
                <h3>🤖 AI Explanation</h3>
                <p>${formatAIExplanation(data.ai_explanation)}</p>
            </div>
        `
        : "";

    resultContainer.innerHTML = `
        <div class="result-card">

            <h2>URL Analysis</h2>

            <p>
                <strong>Risk:</strong>
                <span class="risk-${data.risk.toLowerCase()}">
                    ${escapeHtml(data.risk)}
                </span>
            </p>

            <p>
                <strong>Risk Score:</strong>
                ${data.score}/100
            </p>

            <p>
                <strong>Hostname:</strong>
                ${escapeHtml(data.hostname)}
            </p>

            <p>
                <strong>Protocol:</strong>
                ${escapeHtml(data.scheme.toUpperCase())}
            </p>

            <h3>Detected Indicators</h3>

            <ul>
                ${indicators}
            </ul>

            ${aiExplanation}

            ${disclaimer()}
        </div>
    `;
}


function disclaimer() {
    return `
        <p class="disclaimer">
            CyberBuddy identifies security indicators and provides
            guidance. A risk level is not definitive proof that
            something is malicious.
        </p>
    `;
}


function showStatus(message) {
    statusMessage.textContent = message;
}


function setLoading(isLoading) {
    analyzeButton.disabled = isLoading;

    if (isLoading) {
        analyzeButton.textContent =
            currentMode === "message"
                ? "Analyzing Message..."
                : "Analyzing URL...";
    } else {
        analyzeButton.textContent =
            currentMode === "message"
                ? "Analyze Message"
                : "Analyze URL";
    }
}

function formatAIExplanation(text) {
    return escapeHtml(text)
        .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
        .replace(/\n/g, "<br>");
}

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value;
    return div.innerHTML;
}