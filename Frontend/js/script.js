// =========================================================
// SCREEN SYSTEM NAVIGATION
// =========================================================

function hideAllScreens() {
    document.querySelectorAll(".screen").forEach(function (screen) {
        screen.classList.remove("active");
    });
}

function showLogin() {
    hideAllScreens();
    document.getElementById("login-screen").classList.add("active");
}

function showRegister() {
    hideAllScreens();
    document.getElementById("register-screen").classList.add("active");
}

function showRecovery() {
    hideAllScreens();
    document.getElementById("recovery-screen").classList.add("active");
}

function showAuthenticator() {
    hideAllScreens();
    document.getElementById("authenticator-screen").classList.add("active");
}

function showTwoFactorScreen() {
    hideAllScreens();
    document.getElementById("two-factor-screen").classList.add("active");
    const codeInput = document.getElementById("two-factor-code");
    if (codeInput) codeInput.focus();
}

function showRecoveryCodes() {
    hideAllScreens();
    document.getElementById("recovery-codes-screen").classList.add("active");
}

async function showDashboard() {
    hideAllScreens();
    document.getElementById("dashboard-screen").classList.add("active");
    await loadDashboardData();
}

function scrollToDelegations() {
    const el = document.getElementById("inboundDelegationsSection");
    if (el) el.scrollIntoView({ behavior: "smooth" });
}

// =========================================================
// WEBAUTHN HELPERS & FUNCTIONS
// =========================================================

function base64urlToBuffer(base64url) {
    const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
    const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        buffer[i] = binary.charCodeAt(i);
    }
    return buffer.buffer;
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function credentialToJSON(credential) {
    const response = credential.response;
    const result = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type
    };

    if (response.attestationObject) {
        result.response = {
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
            attestationObject: bufferToBase64url(response.attestationObject)
        };
    } else {
        result.response = {
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
            authenticatorData: bufferToBase64url(response.authenticatorData),
            signature: bufferToBase64url(response.signature),
            userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null
        };
    }
    return result;
}

async function loginWithPasskey() {
    const email = document.getElementById("login-email").value.trim();
    const error = document.getElementById("webauthn-login-error");

    if (error) { error.hidden = true; error.textContent = ""; }

    if (!email) {
        if (error) { error.textContent = "Please enter your email first."; error.hidden = false; }
        return;
    }

    try {
        const optionsResponse = await fetch("/webauthn/login/options", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: email })
        });

        const optionsData = await optionsResponse.json();
        if (!optionsResponse.ok) throw new Error(optionsData.error || "Unable to start passkey login.");

        optionsData.challenge = base64urlToBuffer(optionsData.challenge);
        if (optionsData.allowCredentials) {
            optionsData.allowCredentials = optionsData.allowCredentials.map(credential => ({
                ...credential,
                id: base64urlToBuffer(credential.id)
            }));
        }

        const credential = await navigator.credentials.get({ publicKey: optionsData });
        if (!credential) throw new Error("Passkey authentication was cancelled.");

        const verifyResponse = await fetch("/webauthn/login/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(credentialToJSON(credential))
        });

        const verifyData = await verifyResponse.json();
        if (!verifyResponse.ok) throw new Error(verifyData.error || "Passkey authentication failed.");

        showDashboard();
    } catch (errorMessage) {
        console.error("Passkey login error:", errorMessage);
        if (error) {
            error.textContent = errorMessage.message || "Passkey login failed.";
            error.hidden = false;
        }
    }
}

async function registerFingerprint() {
    const errorElement = document.getElementById("webauthn-register-error");
    if (errorElement) { errorElement.textContent = ""; errorElement.hidden = true; }

    if (!window.PublicKeyCredential) {
        if (errorElement) {
            errorElement.textContent = "Passkeys are not supported by this browser.";
            errorElement.hidden = false;
        }
        return;
    }

    try {
        const response = await fetch("/webauthn/register/options", { method: "POST" });
        const options = await response.json();
        if (!response.ok) throw new Error(options.error || "Unable to start passkey registration.");

        options.challenge = base64urlToBuffer(options.challenge);
        if (options.user && options.user.id) {
            options.user.id = base64urlToBuffer(options.user.id);
        }

        if (options.excludeCredentials) {
            options.excludeCredentials = options.excludeCredentials.map(function (credential) {
                return { ...credential, id: base64urlToBuffer(credential.id) };
            });
        }

        const credential = await navigator.credentials.create({ publicKey: options });
        if (!credential) throw new Error("Passkey registration was cancelled.");

        const verifyResponse = await fetch("/webauthn/register/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(credentialToJSON(credential))
        });

        const result = await verifyResponse.json();
        if (!verifyResponse.ok) throw new Error(result.error || "Passkey registration failed.");

        alert("Passkey registered successfully.");
        showLogin();
    } catch (error) {
        console.error(error);
        if (errorElement) {
            errorElement.textContent = error.message || "Passkey registration failed.";
            errorElement.hidden = false;
        }
    }
}

// =========================================================
// DASHBOARD DATA LOADER & CONTROLLERS
// =========================================================

async function loadDashboardData() {
    try {
        const userRes = await fetch("/api/me");
        if (!userRes.ok) {
            showLogin();
            return;
        }
        const userData = await userRes.json();
        const usernameElem = document.getElementById("dashboardUsername");
        if (usernameElem) {
            usernameElem.textContent = userData.username || userData.email || "User";
        }

        await forceUpdateDMS();
        await loadDelegatesList();
        await loadVaultItems();
        await loadAuditLog();

    } catch (err) {
        console.error("Failed to load dashboard data:", err);
    }
}

async function forceUpdateDMS() {
    try {
        const dmsRes = await fetch("/dms/status");
        if (!dmsRes.ok) return;
        const dms = await dmsRes.json();

        const countdownElem = document.getElementById("countdownDaysRemaining");
        const limitElem = document.getElementById("countdownDaysLimit");
        const lastActivityElem = document.getElementById("lastActivityTime");
        const daysInactiveElem = document.getElementById("daysInactiveText");
        const badgeElem = document.getElementById("dmsStatusBadge");
        const triggerBanner = document.getElementById("triggerAlertBanner");
        const bannerConfirmAt = document.getElementById("bannerConfirmAt");

        if (countdownElem) countdownElem.textContent = Number(dms.days_remaining).toFixed(1);
        if (limitElem) limitElem.textContent = dms.inactivity_days || 30;
        
        if (lastActivityElem) {
            const dateObj = new Date(dms.last_activity);
            lastActivityElem.textContent = isNaN(dateObj) ? dms.last_activity : dateObj.toLocaleString();
        }
        if (daysInactiveElem) daysInactiveElem.textContent = dms.days_inactive;

        if (badgeElem) {
            if (dms.trigger_status === "pending") {
                badgeElem.className = "switch-badge pending";
                badgeElem.textContent = "⚠️ CONTEST WINDOW OPEN (PENDING CONFIRMATION)";
                if (triggerBanner) {
                    triggerBanner.hidden = false;
                    if (bannerConfirmAt) {
                        const cDate = new Date(dms.confirm_at);
                        bannerConfirmAt.textContent = isNaN(cDate) ? dms.confirm_at : cDate.toLocaleString();
                    }
                }
            } else if (dms.trigger_status === "confirmed") {
                badgeElem.className = "switch-badge confirmed";
                badgeElem.textContent = "💥 DEAD MAN'S SWITCH CONFIRMED (DATA TRANSFERRED)";
                if (triggerBanner) triggerBanner.hidden = true;
            } else {
                badgeElem.className = "switch-badge active";
                badgeElem.textContent = "● SWITCH ARMED (ACTIVE - 30 DAYS INACTIVITY LIMIT)";
                if (triggerBanner) triggerBanner.hidden = true;
            }
        }
    } catch (err) {
        console.error("Failed to load DMS status:", err);
    }
}

setInterval(() => {
    const dashboard = document.getElementById("dashboard-screen");
    if (dashboard && dashboard.classList.contains("active")) {
        forceUpdateDMS();
    }
}, 5000);

async function loadDelegatesList() {
    const res = await fetch("/delegate/list");
    if (!res.ok) return;
    const data = await res.json();

    const outgoingContainer = document.getElementById("outgoingDelegatesList");
    if (outgoingContainer) {
        if (!data.outgoing || data.outgoing.length === 0) {
            outgoingContainer.innerHTML = '<p style="font-family: \'IBM Plex Mono\', monospace; font-size: 0.78rem; color: var(--dim);">No delegates assigned yet. Add one above to protect your account.</p>';
        } else {
            outgoingContainer.innerHTML = data.outgoing.map(d => `
                <div class="item-row">
                    <div class="item-info">
                        <strong>${escapeHTML(d.username)} (${escapeHTML(d.email)})</strong>
                        <span>Scope: ${escapeHTML(d.scope)} • Status: <span style="color: ${d.status === 'active' ? 'var(--teal)' : 'var(--warning)'}; text-transform: uppercase;">${d.status}</span></span>
                    </div>
                    <button type="button" class="btn-mini danger" onclick="revokeDelegate(${d.delegate_id})">Revoke</button>
                </div>
            `).join("");
        }
    }

    const incomingContainer = document.getElementById("incomingDelegationsList");
    const inviteBanner = document.getElementById("incomingInviteBanner");
    let hasPendingInvite = false;

    if (incomingContainer) {
        if (!data.incoming || data.incoming.length === 0) {
            incomingContainer.innerHTML = '<p style="font-family: \'IBM Plex Mono\', monospace; font-size: 0.78rem; color: var(--dim);">No inbound delegations. When someone designates you as their emergency delegate, it will appear here.</p>';
        } else {
            incomingContainer.innerHTML = data.incoming.map(d => {
                let actionButtons = "";
                if (d.status === "pending") {
                    hasPendingInvite = true;
                    actionButtons = `
                        <div style="display: flex; gap: 8px;">
                            <button type="button" class="btn-mini" onclick="acceptDelegate(${d.delegate_id})">Accept</button>
                            <button type="button" class="btn-mini secondary" onclick="rejectDelegate(${d.delegate_id})">Decline</button>
                        </div>
                    `;
                } else if (d.status === "active") {
                    if (d.switch_status === "confirmed") {
                        actionButtons = `
                            <button type="button" class="btn-mini checkin-btn" style="background: var(--teal); color: #000; font-weight: bold;" onclick="accessTransferredData(${d.delegate_id})">
                                🔓 UNLOCK TRANSFERRED VAULT DATA
                            </button>
                        `;
                    } else {
                        actionButtons = `<span class="item-tag">Active Trustee (Switch Armed)</span>`;
                    }
                }

                return `
                    <div class="item-row">
                        <div class="item-info">
                            <strong>Owner: ${escapeHTML(d.owner_username)} (${escapeHTML(d.owner_email)})</strong>
                            <span>Scope: ${escapeHTML(d.scope)} • Switch Status: <strong style="color: ${d.switch_status === 'confirmed' ? 'var(--danger)' : 'var(--teal)'};">${d.switch_status.toUpperCase()}</strong></span>
                        </div>
                        ${actionButtons}
                    </div>
                `;
            }).join("");
        }
    }

    if (inviteBanner) {
        inviteBanner.hidden = !hasPendingInvite;
    }
}

async function loadVaultItems() {
    const res = await fetch("/api/vault");
    if (!res.ok) return;
    const rawData = await res.json();
    
    // Fix: Handle both Array format (app.py) and Object format (app_2.py)
    const items = Array.isArray(rawData) ? rawData : rawData.items;
    
    const container = document.getElementById("vaultItemsList");
    if (!container) return;

    if (!items || items.length === 0) {
        container.innerHTML = '<p style="font-family: \'IBM Plex Mono\', monospace; font-size: 0.78rem; color: var(--dim);">Secure vault is empty. Store credentials or instructions above to be transferred.</p>';
    } else {
        container.innerHTML = items.map(item => `
            <div class="item-row">
                <div class="item-info">
                    <strong style="color: var(--ink); font-size: 1rem; display: block; margin-bottom: 4px;">${escapeHTML(item.title)}</strong>
                    <span style="font-size: 0.75rem; color: var(--muted);">Category: ${escapeHTML(item.category)} • Confidential Content Encrypted</span>
                </div>
                <button type="button" class="btn-mini danger" onclick="deleteVaultItem(${item.vault_id})">Delete</button>
            </div>
        `).join("");
    }
}


async function loadAuditLog() {
    const res = await fetch("/audit-log");
    if (!res.ok) return;
    const items = await res.json();
    const container = document.getElementById("auditLogContainer");
    if (!container) return;

    if (!items || items.length === 0) {
        container.innerHTML = '<p style="font-family: \'IBM Plex Mono\', monospace; font-size: 0.78rem; color: var(--dim);">No activity logged yet.</p>';
    } else {
        container.innerHTML = items.slice(0, 15).map(item => {
            const time = new Date(item.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            return `
                <div style="font-family: 'IBM Plex Mono', monospace; font-size: 0.75rem; padding: 6px 0; border-bottom: 1px solid #222; display: flex; justify-content: space-between;">
                    <span><strong style="color: var(--teal);">[${time}]</strong> ${escapeHTML(item.action)}: ${escapeHTML(item.details || "")}</span>
                    <span style="color: var(--muted);">${escapeHTML(item.actor_type)}</span>
                </div>
            `;
        }).join("");
    }
}

function escapeHTML(str) {
    if (!str) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// =========================================================
// DASHBOARD ACTIONS (Check-In, Vault, Delegates)
// =========================================================

// =========================================================
// DASHBOARD ACTIONS: Secure Check-In (I'm Alive)
// =========================================================

function openCheckInModal() {
    const m = document.getElementById("checkInModal");
    if (m) m.classList.add("active");
}

function closeCheckInModal() {
    const m = document.getElementById("checkInModal");
    if (m) m.classList.remove("active");
    const err = document.getElementById("checkin-error");
    if (err) err.hidden = true;
}

const btnCheckIn = document.getElementById("btnCheckIn");
if (btnCheckIn) {
    // Clone to strip the old direct-fetch listener you just deleted
    const newBtnCheckIn = btnCheckIn.cloneNode(true);
    btnCheckIn.parentNode.replaceChild(newBtnCheckIn, btnCheckIn);
    
    // Now it just opens the modal instead of instantly fetching
    newBtnCheckIn.addEventListener("click", openCheckInModal);
}

const btnSubmitCheckIn = document.getElementById("btnSubmitCheckIn");
if (btnSubmitCheckIn) {
    btnSubmitCheckIn.addEventListener("click", async function () {
        const otp = document.getElementById("checkin-otp")?.value.trim();
        const errElem = document.getElementById("checkin-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        if (!otp) {
            if (errElem) { errElem.textContent = "Please enter verification code."; errElem.hidden = false; }
            return;
        }

        const formData = new FormData();
        formData.append("otp", otp);

        try {
            const res = await fetch("/dms/check-in", { method: "POST", body: formData });
            const data = await res.json();
            
            if (res.ok) {
                alert("⚡ " + data.message);
                closeCheckInModal();
                document.getElementById("checkin-otp").value = "";
                
                // Force dashboard to instantly refresh the countdown
                if (typeof forceUpdateDMS === "function") forceUpdateDMS();
                if (typeof loadDashboardData === "function") loadDashboardData();
            } else {
                if (errElem) { errElem.textContent = data.error || "Check-in failed."; errElem.hidden = false; }
            }
        } catch (e) {
            console.error("Check-in Error:", e);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}
const saveVaultForm = document.getElementById("save-vault-form");
if (saveVaultForm) {
    saveVaultForm.addEventListener("submit", async function (e) {
        e.preventDefault(); 
        const errElem = document.getElementById("vault-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        const payload = {
            title: saveVaultForm.elements["title"].value.trim(),
            category: saveVaultForm.elements["category"].value,
            secret_content: saveVaultForm.elements["secret_content"].value.trim()
        };

        try {
            const res = await fetch("/api/vault/save", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            
            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Failed to save."; errElem.hidden = false; }
                return;
            }
            alert("✅ Secure vault item saved!");
            saveVaultForm.reset();
            await loadDashboardData();
        } catch (err) {
            console.error(err);
        }
    });
}

async function deleteVaultItem(vaultId) {
    if (!confirm("Remove this item from your secure vault?")) return;
    try {
        const res = await fetch(`/api/vault/delete/${vaultId}`, { method: "POST" });
        if (res.ok) await loadDashboardData();
    } catch (e) {
        console.error(e);
    }
}

const addDelegateForm = document.getElementById("add-delegate-form");
if (addDelegateForm) {
    addDelegateForm.addEventListener("submit", async function (e) {
        e.preventDefault(); 
        const errElem = document.getElementById("add-delegate-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        // Fetch exactly as FormData to match backend expectations
        const formData = new FormData(addDelegateForm);

        try {
            const res = await fetch("/delegate/add", {
                method: "POST",
                body: formData
            });
            const data = await res.json();
            
            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Failed to invite delegate."; errElem.hidden = false; }
                return;
            }
            alert("✅ " + (data.message || "Delegate added successfully!"));
            addDelegateForm.reset();
            
            if (typeof loadDashboardData === "function") loadDashboardData();
        } catch (err) {
            console.error(err);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}

async function acceptDelegate(delegateId) {
    try {
        const res = await fetch(`/delegate/accept/${delegateId}`, { method: "POST" });
        const data = await res.json();
        if (res.ok) {
            alert("Delegation accepted!");
            await loadDashboardData();
        } else {
            alert(data.error || "Failed to accept delegation");
        }
    } catch (e) { console.error(e); }
}

async function rejectDelegate(delegateId) {
    if (!confirm("Are you sure you want to decline this delegation invitation?")) return;
    try {
        const res = await fetch(`/delegate/reject/${delegateId}`, { method: "POST" });
        if (res.ok) await loadDashboardData();
    } catch (e) { console.error(e); }
}

async function revokeDelegate(delegateId) {
    if (!confirm("Are you sure you want to revoke access for this delegate?")) return;
    try {
        const res = await fetch(`/delegate/revoke/${delegateId}`, { method: "POST" });
        if (res.ok) await loadDashboardData();
    } catch (e) { console.error(e); }
}

async function accessTransferredData(delegateId) {
    try {
        const res = await fetch(`/delegate/transferred-data/${delegateId}`);
        const data = await res.json();
        if (!res.ok) {
            alert(data.error || "Access denied.");
            return;
        }

        const modal = document.getElementById("transferredDataModal");
        const content = document.getElementById("transferredDataContent");
        if (!modal || !content) return;

        if (!data.items || data.items.length === 0) {
            content.innerHTML = `<p style="color: var(--muted); font-family: 'IBM Plex Mono', monospace;">The account owner (${escapeHTML(data.owner_username)}) had no items saved in their vault.</p>`;
        } else {
            content.innerHTML = `
                <p style="color: var(--teal); font-family: 'IBM Plex Mono', monospace; margin-bottom: 12px;">
                    Account Owner: <strong>${escapeHTML(data.owner_username)}</strong> • Scope: ${escapeHTML(data.scope)}
                </p>
                ${data.items.map(item => `
                    <div class="transferred-card">
                        <strong style="color: var(--ink); font-size: 1rem;">${escapeHTML(item.title)}</strong>
                        <span style="font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; color: var(--dim); display: block;">Category: ${escapeHTML(item.category)} • Updated: ${item.updated_at}</span>
                        <pre>${escapeHTML(item.secret_content)}</pre>
                    </div>
                `).join("")}
            `;
        }

        modal.classList.add("active");
    } catch (e) {
        console.error(e);
        alert("Failed to retrieve transferred data.");
    }
}

function closeTransferredDataModal() {
    const m = document.getElementById("transferredDataModal");
    if (m) m.classList.remove("active");
}

function openCancelTriggerModal() {
    const m = document.getElementById("cancelTriggerModal");
    if (m) m.classList.add("active");
}

function closeCancelTriggerModal() {
    const m = document.getElementById("cancelTriggerModal");
    if (m) m.classList.remove("active");
}

const btnSubmitCancelTrigger = document.getElementById("btnSubmitCancelTrigger");
if (btnSubmitCancelTrigger) {
    btnSubmitCancelTrigger.addEventListener("click", async function () {
        const otp = document.getElementById("cancel-otp")?.value.trim();
        const errElem = document.getElementById("cancel-trigger-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        if (!otp) {
            if (errElem) { errElem.textContent = "Please enter verification code or password."; errElem.hidden = false; }
            return;
        }

        const formData = new FormData();
        formData.append("otp", otp);

        try {
            const res = await fetch("/dms/cancel-trigger", { method: "POST", body: formData });
            const data = await res.json();
            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Cancellation failed."; errElem.hidden = false; }
                return;
            }
            alert(data.message || "Dead Man's Switch trigger cancelled successfully!");
            closeCancelTriggerModal();
            await loadDashboardData();
        } catch (e) {
            console.error(e);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}

// =========================================================
// HACKATHON DEMO SANDBOX CONTROLS
// =========================================================

const btnDemoSimulateInactive = document.getElementById("btnDemoSimulateInactive");
if (btnDemoSimulateInactive) {
    btnDemoSimulateInactive.addEventListener("click", async function () {
        if (!confirm("Simulate 31 days of inactivity? This will automatically trigger the switch and transfer your vault data.")) return;
        try {
            const res = await fetch("/dms/simulate-inactive", { method: "POST" });
            const data = await res.json();
            if (res.ok) {
                alert("⏳ " + data.message);
                await loadDashboardData();
                
                // Automatically trigger the confirmation step for instant transfer
                const confirmBtn = document.getElementById("btnDemoSimulateConfirm");
                if (confirmBtn) confirmBtn.click();
                
            } else {
                alert(data.error || "Simulation failed");
            }
        } catch (e) { console.error(e); }
    });
}

const btnDemoSimulateConfirm = document.getElementById("btnDemoSimulateConfirm");
if (btnDemoSimulateConfirm) {
    btnDemoSimulateConfirm.addEventListener("click", async function () {
        if (!confirm("Force switch confirmation? This will immediately unlock your transferred vault data for your active delegate to test!")) return;
        try {
            const res = await fetch("/dms/simulate-confirm", { method: "POST" });
            const data = await res.json();
            if (res.ok) {
                alert("💥 " + data.message);
                await loadDashboardData();
            } else {
                alert(data.error || "Simulation failed");
            }
        } catch (e) { console.error(e); }
    });
}

const btnDemoCancelTrigger = document.getElementById("btnDemoCancelTrigger");
if (btnDemoCancelTrigger) {
    btnDemoCancelTrigger.addEventListener("click", openCancelTriggerModal);
}

// =========================================================
// AUTHENTICATION: REGISTER, LOGIN, 2FA
// =========================================================

document.querySelectorAll(".logo-link").forEach(function (link) {
    link.addEventListener("click", function (event) {
        event.preventDefault();
        showLogin();
    });
});

const registerForm = document.getElementById("register-form");
if (registerForm) {
    registerForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        const password = document.getElementById("register-password").value;
        const confirmation = document.getElementById("register-password-confirmation").value;

        if (password !== confirmation) {
            alert("Passwords do not match.");
            return;
        }

        const registeredEmail = document.getElementById("register-email").value.trim();
        const formData = new FormData(registerForm);

        try {
            const response = await fetch("/register", { method: "POST", body: formData });
            const data = await response.json();

            if (!response.ok) {
                alert(data.error || "Registration failed.");
                return;
            }

            alert("✅ Account created successfully! Please log in.");
            const loginEmailInput = document.getElementById("login-email");
            if (loginEmailInput) loginEmailInput.value = registeredEmail;

            registerForm.reset();
            showLogin();
            
            const loginPasswordInput = document.getElementById("login-password");
            if (loginPasswordInput) loginPasswordInput.focus();

        } catch (error) {
            console.error(error);
            alert("Unable to connect to the ReAnchor server.");
        }
    });
}

const loginForm = document.getElementById("login-form");
if (loginForm) {
    loginForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        const formData = new FormData(loginForm);
        try {
            const response = await fetch("/login", { method: "POST", body: formData });
            const data = await response.json();

            if (!response.ok) {
                alert(data.error || "Login failed.");
                return;
            }

            if (data.status === "2fa_required") {
                showTwoFactorScreen();
                return;
            }

            if (data.status === "ok") {
                await setupAuthenticator();
            }
        } catch (error) {
            console.error(error);
            alert("Unable to connect to the ReAnchor server.");
        }
    });
}

async function setupAuthenticator() {
    try {
        const response = await fetch("/2fa/setup", { method: "POST" });
        const data = await response.json();

        if (!response.ok) {
            alert(data.error || "Unable to set up authenticator.");
            return;
        }

        const qr = document.getElementById("totp-qr");
        if (qr) qr.src = data.qr_code;

        const setupKey = document.getElementById("setup-key");
        if (setupKey) setupKey.textContent = data.setup_key;

        const setupCode = document.getElementById("setup-code");
        if (setupCode) setupCode.value = "";

        const errorElement = document.getElementById("totp-error");
        if (errorElement) { errorElement.textContent = ""; errorElement.hidden = true; }

        showAuthenticator();
    } catch (error) {
        console.error(error);
        alert("Unable to connect to the ReAnchor server.");
    }
}

const activateTotpButton = document.getElementById("activate-totp");
if (activateTotpButton) {
    activateTotpButton.addEventListener("click", async function () {
        const otp = document.getElementById("setup-code").value.trim();
        const errorElement = document.getElementById("totp-error");

        if (errorElement) { errorElement.textContent = ""; errorElement.hidden = true; }

        if (!/^\d{6}$/.test(otp)) {
            if (errorElement) {
                errorElement.textContent = "Please enter a valid 6-digit verification code.";
                errorElement.hidden = false;
            }
            return;
        }

        const formData = new FormData();
        formData.append("otp", otp);

        try {
            const response = await fetch("/2fa/verify", { method: "POST", body: formData });
            const data = await response.json();

            if (!response.ok) {
                if (errorElement) {
                    errorElement.textContent = data.error || "Invalid verification code.";
                    errorElement.hidden = false;
                }
                return;
            }

            if (data.status === "enabled") {
                document.getElementById("setup-code").value = "";
                displayRecoveryCodes(data.recovery_codes);
                showRecoveryCodes();
            }
        } catch (error) {
            console.error(error);
            if (errorElement) {
                errorElement.textContent = "Unable to connect to the server.";
                errorElement.hidden = false;
            }
        }
    });
}

function displayRecoveryCodes(codes) {
    const list = document.getElementById("recovery-codes-list");
    if (!list) return;
    list.innerHTML = "";

    codes.forEach(function (code) {
        const codeElement = document.createElement("div");
        codeElement.textContent = code;
        list.appendChild(codeElement);
    });

    const downloadButton = document.getElementById("download-recovery-codes");
    if (downloadButton) {
        downloadButton.onclick = function () {
            const text = "ReAnchor Emergency Recovery Codes\n" +
                         "===================================\n\n" +
                         codes.join("\n") +
                         "\n\nKeep these codes secure. They can recover your identity.";
            const blob = new Blob([text], { type: "text/plain" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = "ReAnchor-Recovery-Codes.txt";
            link.click();
            URL.revokeObjectURL(url);
        };
    }
}

const confirmRecoveryButton = document.getElementById("confirm-recovery-code");
if (confirmRecoveryButton) {
    confirmRecoveryButton.addEventListener("click", async function () {
        const saved = document.getElementById("recovery-saved").checked;
        const code = document.getElementById("recovery-confirm-code").value.trim();
        const errorElement = document.getElementById("recovery-confirm-error");

        if (errorElement) { errorElement.textContent = ""; errorElement.hidden = true; }

        if (!saved) {
            if (errorElement) {
                errorElement.textContent = "Please confirm that you have saved your recovery codes.";
                errorElement.hidden = false;
            }
            return;
        }

        if (code.length !== 16) {
            if (errorElement) {
                errorElement.textContent = "Please enter a valid 16-character recovery code.";
                errorElement.hidden = false;
            }
            return;
        }

        const formData = new FormData();
        formData.append("code", code);

        try {
            const response = await fetch("/recovery/confirm", { method: "POST", body: formData });
            const data = await response.json();

            if (!response.ok) {
                if (errorElement) {
                    errorElement.textContent = data.error || "Invalid recovery code.";
                    errorElement.hidden = false;
                }
                return;
            }

            if (data.status === "confirmed") {
                alert("✅ Recovery code confirmed securely! Your backup is verified.");
                const webauthnSection = document.getElementById("webauthn-section");
                if (webauthnSection) webauthnSection.hidden = false;
                confirmRecoveryButton.disabled = true;
            }
        } catch (error) {
            console.error(error);
            if (errorElement) {
                errorElement.textContent = "Unable to connect to the ReAnchor server.";
                errorElement.hidden = false;
            }
        }
    });
}

const saveKnowledgeAnchor = document.getElementById("save-knowledge-anchor");
if (saveKnowledgeAnchor) {
    saveKnowledgeAnchor.addEventListener("click", async function () {
        const question = document.getElementById("knowledge-question").value;
        const answer = document.getElementById("knowledge-answer").value;
        const errorElement = document.getElementById("knowledge-anchor-error");

        errorElement.hidden = true;
        errorElement.textContent = "";

        if (!question || !answer.trim()) {
            errorElement.textContent = "Select a question and enter an answer.";
            errorElement.hidden = false;
            return;
        }

        try {
            const response = await fetch("/knowledge-anchor", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    question_id: Number(question),
                    answer: answer
                })
            });

            const data = await response.json();
            if (!response.ok) throw new Error(data.error || "Unable to save knowledge anchor.");

            document.getElementById("knowledge-anchor-section").hidden = true;
            const webauthnSection = document.getElementById("webauthn-section");
            if (webauthnSection) webauthnSection.hidden = false;
        } catch (error) {
            console.error("Knowledge Anchor Error:", error);
            errorElement.textContent = error.message || "Unable to save knowledge anchor.";
            errorElement.hidden = false;
        }
    });
}

const registerPasskeyButton = document.getElementById("register-passkey");
if (registerPasskeyButton) registerPasskeyButton.addEventListener("click", registerFingerprint);

const passkeyLoginButton = document.getElementById("passkey-login");
if (passkeyLoginButton) passkeyLoginButton.addEventListener("click", loginWithPasskey);

const passkey2FAButton = document.getElementById("use-passkey-2fa");
if (passkey2FAButton) passkey2FAButton.addEventListener("click", loginWithPasskey);

const twoFactorForm = document.getElementById("two-factor-form");
if (twoFactorForm) {
    twoFactorForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        const otp = document.getElementById("two-factor-code").value.trim();
        const errorElement = document.getElementById("two-factor-error");

        if (errorElement) { errorElement.textContent = ""; errorElement.hidden = true; }

        if (!/^\d{6}$/.test(otp)) {
            if (errorElement) {
                errorElement.textContent = "Please enter a valid 6-digit code.";
                errorElement.hidden = false;
            }
            return;
        }

        const formData = new FormData();
        formData.append("otp", otp);

        try {
            const response = await fetch("/2fa/challenge", { method: "POST", body: formData });
            const data = await response.json();

            if (!response.ok) {
                if (errorElement) {
                    errorElement.textContent = data.error || "Invalid verification code.";
                    errorElement.hidden = false;
                }
                return;
            }

            if (data.status === "ok") {
                twoFactorForm.reset();
                showDashboard();
            }
        } catch (error) {
            console.error(error);
            if (errorElement) {
                errorElement.textContent = "Unable to connect to the ReAnchor server.";
                errorElement.hidden = false;
            }
        }
    });
}

// =========================================================
// DYNAMIC RECOVERY FLOW (Email -> Code OR Knowledge Anchor)
// =========================================================

function resetRecoveryUI() {
    const initF = document.getElementById("recovery-init-form");
    const codeF = document.getElementById("recovery-code-form");
    const knowF = document.getElementById("recovery-knowledge-form");
    
    if (initF) { initF.hidden = false; initF.reset(); }
    if (codeF) { codeF.hidden = true; codeF.reset(); }
    if (knowF) { knowF.hidden = true; knowF.reset(); }
    
    document.querySelectorAll("#recovery-screen .setup-error").forEach(el => el.hidden = true);
}

// STEP 1: Find Account by Email
const recoveryInitForm = document.getElementById("recovery-init-form");
if (recoveryInitForm) {
    recoveryInitForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        const email = document.getElementById("recovery-email").value.trim();
        const errElem = document.getElementById("recovery-init-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        try {
            const res = await fetch("/recovery/init", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: email })
            });
            const data = await res.json();

            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Failed to find account."; errElem.hidden = false; }
                return;
            }

            recoveryInitForm.hidden = true;

            if (data.method === "code") {
                document.getElementById("recovery-code-form").hidden = false;
                const msgElem = document.getElementById("recovery-code-msg");
                if (msgElem) msgElem.textContent = data.message;
            } else if (data.method === "knowledge") {
                document.getElementById("recovery-knowledge-form").hidden = false;
                const qElem = document.getElementById("recovery-question-text");
                if (qElem) qElem.textContent = data.question;
            }
        } catch (err) {
            console.error(err);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}

// STEP 2A: Submit Recovery Code
const recoveryCodeForm = document.getElementById("recovery-code-form");
if (recoveryCodeForm) {
    recoveryCodeForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        const code = document.getElementById("recovery-code").value.trim();
        const errElem = document.getElementById("recovery-code-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        if (code.length !== 16) {
            if (errElem) { errElem.textContent = "Code must be 16 characters."; errElem.hidden = false; }
            return;
        }

        const formData = new FormData();
        formData.append("recovery_code", code);

        try {
            const res = await fetch("/recovery", { method: "POST", body: formData });
            const data = await res.json();

            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Verification failed."; errElem.hidden = false; }
                return;
            }
            
            resetRecoveryUI();
            showDashboard();
        } catch (err) {
            console.error(err);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}

// STEP 2B: Submit Knowledge Anchor Answer
const recoveryKnowledgeForm = document.getElementById("recovery-knowledge-form");
if (recoveryKnowledgeForm) {
    recoveryKnowledgeForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        const email = document.getElementById("recovery-email").value.trim();
        const answer = document.getElementById("recovery-answer").value;
        const errElem = document.getElementById("recovery-knowledge-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        try {
            const res = await fetch("/recovery/knowledge", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: email, answer: answer })
            });
            const data = await res.json();

            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Incorrect answer."; errElem.hidden = false; }
                return;
            }
            
            resetRecoveryUI();
            showDashboard();
        } catch (err) {
            console.error(err);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}

const logoutButton = document.getElementById("logoutBtn");
if (logoutButton) {
    logoutButton.addEventListener("click", async function () {
        try {
            await fetch("/logout", { method: "POST" });
        } catch (error) {
            console.error("Logout error:", error);
        }
        showLogin();
    });
}

const registerPassword = document.getElementById("register-password");
const strengthFill = document.getElementById("password-strength-fill");
const strengthText = document.getElementById("password-strength-text");

if (registerPassword) {
    registerPassword.addEventListener("input", function () {
        const password = registerPassword.value;
        let score = 0;

        if (password.length >= 12) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;

        if (password.length === 0) {
            strengthText.textContent = "Password strength: Weak";
            strengthFill.style.width = "0%";
        } else if (score <= 2) {
            strengthText.textContent = "Password strength: Weak";
            strengthFill.style.width = "33%";
        } else if (score <= 4) {
            strengthText.textContent = "Password strength: Medium";
            strengthFill.style.width = "66%";
        } else {
            strengthText.textContent = "Password strength: Strong";
            strengthFill.style.width = "100%";
        }
    });
}

// On page load: check if already authenticated
window.addEventListener("DOMContentLoaded", async function () {
    try {
        const res = await fetch("/api/me");
        if (res.ok) {
            const data = await res.json();
            if (data.authenticated || data.username) {
                showDashboard();
                return;
            }
        }
    } catch (e) {}
    showLogin();
});

// =========================================================
// CRITICAL FIX: RECOVERY FORMS (Stops page reload to login)
// =========================================================

function resetRecoveryUI() {
    const initF = document.getElementById("recovery-init-form");
    const codeF = document.getElementById("recovery-code-form");
    const knowF = document.getElementById("recovery-knowledge-form");
    
    if (initF) { initF.hidden = false; initF.reset(); }
    if (codeF) { codeF.hidden = true; codeF.reset(); }
    if (knowF) { knowF.hidden = true; knowF.reset(); }
    
    document.querySelectorAll("#recovery-screen .setup-error").forEach(el => el.hidden = true);
}

// 1. Fix Recovery Init Form (Email check)
const oldRecoveryInitForm = document.getElementById("recovery-init-form");
if (oldRecoveryInitForm) {
    const newRecoveryInitForm = oldRecoveryInitForm.cloneNode(true);
    oldRecoveryInitForm.parentNode.replaceChild(newRecoveryInitForm, oldRecoveryInitForm);
    
    newRecoveryInitForm.addEventListener("submit", async function(e) {
        e.preventDefault(); // STOPS THE RELOAD
        const email = document.getElementById("recovery-email").value.trim();
        const errElem = document.getElementById("recovery-init-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        try {
            const res = await fetch("/recovery/init", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: email })
            });
            const data = await res.json();

            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Failed to find account."; errElem.hidden = false; }
                return;
            }

            newRecoveryInitForm.hidden = true;

            if (data.method === "code") {
                document.getElementById("recovery-code-form").hidden = false;
                const msgElem = document.getElementById("recovery-code-msg");
                if (msgElem) msgElem.textContent = data.message;
            } else if (data.method === "knowledge") {
                document.getElementById("recovery-knowledge-form").hidden = false;
                const qElem = document.getElementById("recovery-question-text");
                if (qElem) qElem.textContent = data.question;
            }
        } catch (err) {
            console.error(err);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}

// 2. Fix Recovery Code Form
const oldRecoveryCodeForm = document.getElementById("recovery-code-form");
if (oldRecoveryCodeForm) {
    const newRecoveryCodeForm = oldRecoveryCodeForm.cloneNode(true);
    oldRecoveryCodeForm.parentNode.replaceChild(newRecoveryCodeForm, oldRecoveryCodeForm);
    
    newRecoveryCodeForm.addEventListener("submit", async function(e) {
        e.preventDefault(); // STOPS THE RELOAD
        const code = document.getElementById("recovery-code").value.trim();
        const errElem = document.getElementById("recovery-code-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        if (code.length !== 16) {
            if (errElem) { errElem.textContent = "Code must be 16 characters."; errElem.hidden = false; }
            return;
        }

        const formData = new FormData();
        formData.append("recovery_code", code);

        try {
            const res = await fetch("/recovery", { method: "POST", body: formData });
            const data = await res.json();

            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Verification failed."; errElem.hidden = false; }
                return;
            }
            
            resetRecoveryUI();
            if (typeof showDashboard === "function") showDashboard();
        } catch (err) {
            console.error(err);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}

// 3. Fix Recovery Knowledge Form
const oldRecoveryKnowledgeForm = document.getElementById("recovery-knowledge-form");
if (oldRecoveryKnowledgeForm) {
    const newRecoveryKnowledgeForm = oldRecoveryKnowledgeForm.cloneNode(true);
    oldRecoveryKnowledgeForm.parentNode.replaceChild(newRecoveryKnowledgeForm, oldRecoveryKnowledgeForm);
    
    newRecoveryKnowledgeForm.addEventListener("submit", async function(e) {
        e.preventDefault(); // STOPS THE RELOAD
        const email = document.getElementById("recovery-email").value.trim();
        const answer = document.getElementById("recovery-answer").value;
        const errElem = document.getElementById("recovery-knowledge-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        try {
            const res = await fetch("/recovery/knowledge", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: email, answer: answer })
            });
            const data = await res.json();

            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Incorrect answer."; errElem.hidden = false; }
                return;
            }
            
            resetRecoveryUI();
            if (typeof showDashboard === "function") showDashboard();
        } catch (err) {
            console.error(err);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}

// 4. BACKUP: If you are still using the old single-step legacy HTML form
const oldLegacyRecoveryForm = document.getElementById("recovery-form");
if (oldLegacyRecoveryForm) {
    const newLegacyRecoveryForm = oldLegacyRecoveryForm.cloneNode(true);
    oldLegacyRecoveryForm.parentNode.replaceChild(newLegacyRecoveryForm, oldLegacyRecoveryForm);
    
    newLegacyRecoveryForm.addEventListener("submit", async function(e) {
        e.preventDefault(); // STOPS THE RELOAD
        const code = document.getElementById("recovery-code").value.trim();
        const errElem = document.getElementById("recovery-error");
        if (errElem) { errElem.textContent = ""; errElem.hidden = true; }

        if (code.length !== 16) {
            if (errElem) { errElem.textContent = "Code must be 16 characters."; errElem.hidden = false; }
            return;
        }

        const formData = new FormData();
        formData.append("recovery_code", code);

        try {
            const res = await fetch("/recovery", { method: "POST", body: formData });
            const data = await res.json();

            if (!res.ok) {
                if (errElem) { errElem.textContent = data.error || "Verification failed."; errElem.hidden = false; }
                return;
            }
            
            newLegacyRecoveryForm.reset();
            if (typeof showDashboard === "function") showDashboard();
        } catch (err) {
            console.error(err);
            if (errElem) { errElem.textContent = "Connection error."; errElem.hidden = false; }
        }
    });
}

// =========================================================
// SOC THREAT MONITOR DASHBOARD LOGIC
// =========================================================

const btnOpenThreatMonitor = document.getElementById("btnOpenThreatMonitor");
if (btnOpenThreatMonitor) {
    btnOpenThreatMonitor.addEventListener("click", function() {
        // Use your app's built-in screen hiding function
        hideAllScreens(); 
        
        // Show the Threat Dashboard
        const threatScreen = document.getElementById("threat-dashboard-screen");
        if (threatScreen) {
            threatScreen.hidden = false;
            threatScreen.classList.add("active");
        }
    });
}

// The Ping Trace Animation
async function pingAttacker(ip) {
    const consoleLog = document.getElementById("threat-console-log");
    consoleLog.innerHTML += `<br><span style="color: var(--teal); font-weight: bold;">[TRACE] Initiating ICMP echo request and geolocation for ${ip}...</span><br>`;
    
    // Simulate ping packets
    for(let i=1; i<=4; i++) {
        await new Promise(r => setTimeout(r, 600)); // Delay between pings
        consoleLog.innerHTML += `<span style="color: var(--dim);">Reply from ${ip}: bytes=32 time=${Math.floor(Math.random() * 50) + 12}ms TTL=54</span><br>`;
        consoleLog.parentElement.scrollTop = consoleLog.parentElement.scrollHeight;
    }
    
    await new Promise(r => setTimeout(r, 800));
    consoleLog.innerHTML += `<span style="color: var(--warning); font-weight: bold;">[GEO-INTEL] IP Resolved: 185.15.59.224 (Moscow, RU) - Known VPN Node</span><br><br>`;
    consoleLog.parentElement.scrollTop = consoleLog.parentElement.scrollHeight;
}

const btnSimulateAttack = document.getElementById("btnSimulateAttack");
if (btnSimulateAttack) {
    const newBtnSimulateAttack = btnSimulateAttack.cloneNode(true);
    btnSimulateAttack.parentNode.replaceChild(newBtnSimulateAttack, btnSimulateAttack);

    newBtnSimulateAttack.addEventListener("click", async function () {
        const consoleLog = document.getElementById("threat-console-log");
        
        const targetEmail = prompt("Enter the target account email to attack (e.g. saisabs@gmail.com):");
        if (!targetEmail) return;
        
        consoleLog.innerHTML += `<span style="color: var(--warning);">[SYSTEM] Initiating dictionary attack against /recovery/knowledge for target: ${targetEmail}...</span><br>`;
        
        const dictionaryGuesses = ["password123", "pizza", "pineapple", "windows", "linux", "macOS", "batman"];
        newBtnSimulateAttack.disabled = true;
        newBtnSimulateAttack.textContent = "Attack in Progress...";

        for (let i = 0; i < dictionaryGuesses.length; i++) {
            const guess = dictionaryGuesses[i];
            await new Promise(r => setTimeout(r, 500)); 

            consoleLog.innerHTML += `<span style="color: var(--danger);">[ATTACK] Sending payload: {"answer": "${guess}"}</span><br>`;
            
            try {
                const res = await fetch("/recovery/knowledge", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email: targetEmail, answer: guess })
                });
                const data = await res.json();

                if (res.status === 429 || data.defense_triggered) {
                    // DEFENSE WON! Extract IP and push to Defense Matrix UI
                    const badIp = data.attacker_ip || "127.0.0.1";
                    consoleLog.innerHTML += `<span style="color: var(--teal); font-weight: bold;">[DEFENSE] BLOCKED: Automated rate-limit triggered! Attacker IP (${badIp}) blacklisted.</span><br>`;
                    
                    const blockedList = document.getElementById("blocked-ips-list");
                    if (blockedList.innerHTML.includes("No active threats")) blockedList.innerHTML = "";
                    
                    // Add Ping button to the UI
                    blockedList.innerHTML += `
                        <div style="background: #1a1a1a; padding: 10px; border: 1px solid #333; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: var(--danger); font-family: 'IBM Plex Mono', monospace;">${badIp}</span>
                            <button class="btn-mini" onclick="pingAttacker('${badIp}')" style="margin: 0; background: var(--teal); color: #000;">Trace / Ping</button>
                        </div>
                    `;
                    break;
                } else if (res.status === 401) {
                    consoleLog.innerHTML += `<span style="color: var(--warning);">[RESULT] Failed: ${data.error}</span><br>`;
                } else if (res.status === 404) {
                    consoleLog.innerHTML += `<span style="color: var(--muted);">[ERROR] Target account not found.</span><br>`;
                    break;
                }
            } catch (err) {
                consoleLog.innerHTML += `<span style="color: var(--muted);">[ERROR] Connection refused.</span><br>`;
            }
            consoleLog.parentElement.scrollTop = consoleLog.parentElement.scrollHeight;
        }

        consoleLog.innerHTML += `<span style="color: var(--muted);">[SYSTEM] Attack sequence terminated.</span><br><br>`;
        newBtnSimulateAttack.disabled = false;
        newBtnSimulateAttack.textContent = "Launch Dictionary Attack";
    });
}