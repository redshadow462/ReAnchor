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

function showRecoveryCodes() {
    hideAllScreens();

    document
        .getElementById("recovery-codes-screen")
        .classList.add("active");
}

function showTwoFactorScreen() {
    hideAllScreens();

    document
        .getElementById("two-factor-screen")
        .classList.add("active");

    document
        .getElementById("two-factor-code")
        .focus();
}

// Logo → Login
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

        const password =
            document.getElementById("register-password").value;

        const confirmation =
            document.getElementById(
                "register-password-confirmation"
            ).value;

        if (password !== confirmation) {
            alert("Passwords do not match.");
            return;
        }

        const formData = new FormData(registerForm);

        try {
            const response = await fetch("/register", {
                method: "POST",
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                alert(data.error || "Registration failed.");
                return;
            }

            alert("Account created successfully.");

            registerForm.reset();
            showLogin();

        } catch (error) {
            console.error(error);
            alert("Unable to connect to the ReAnchor server.");
        }
    });
}


// =========================
// LOGIN
// =========================

const loginForm = document.getElementById("login-form");

if (loginForm) {
    loginForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const formData = new FormData(loginForm);

        try {
            const response = await fetch("/login", {
                method: "POST",
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                alert(data.error || "Login failed.");
                return;
            }

            // Existing account already has TOTP
            if (data.status === "2fa_required") {
                showTwoFactorChallenge();
                return;
            }

            // First login / TOTP not configured
            if (data.status === "ok") {
                await setupAuthenticator();
                return;
            }

        } catch (error) {
            console.error(error);

            alert(
                "Unable to connect to the ReAnchor server."
            );
        }
    });
}


// =========================
// TOTP SETUP
// =========================

async function setupAuthenticator() {

    try {
        const response = await fetch("/2fa/setup", {
            method: "POST"
        });

        const data = await response.json();

        if (!response.ok) {
            alert(
                data.error ||
                "Unable to set up authenticator."
            );
            return;
        }

        // QR code
        const qr = document.getElementById("totp-qr");

        if (qr) {
            qr.src = data.qr_code;
        }

        // Manual setup key
        const setupKey =
            document.getElementById("setup-key");

        if (setupKey) {
            setupKey.textContent = data.setup_key;
        }

        // Clear previous OTP
        const setupCode =
            document.getElementById("setup-code");

        if (setupCode) {
            setupCode.value = "";
        }

        // Clear previous error
        const errorElement =
            document.getElementById("totp-error");

        if (errorElement) {
            errorElement.textContent = "";
            errorElement.hidden = true;
        }

        // Show authenticator screen
        showAuthenticator();

    } catch (error) {
        console.error(error);

        alert(
            "Unable to connect to the ReAnchor server."
        );
    }
}


// =========================
// ACTIVATE TOTP
// =========================

const activateTotpButton =
    document.getElementById("activate-totp");

if (activateTotpButton) {

    activateTotpButton.addEventListener(
        "click",
        async function () {

            const otp =
                document
                    .getElementById("setup-code")
                    .value
                    .trim();

            const errorElement =
                document.getElementById("totp-error");

            if (errorElement) {
                errorElement.textContent = "";
                errorElement.hidden = true;
            }

            // Validate 6-digit OTP
            if (!/^\d{6}$/.test(otp)) {

                if (errorElement) {
                    errorElement.textContent =
                        "Please enter a valid 6-digit verification code.";

                    errorElement.hidden = false;
                }

                return;
            }

            const formData = new FormData();

            formData.append("otp", otp);

            try {

                const response = await fetch(
                    "/2fa/verify",
                    {
                        method: "POST",
                        body: formData
                    }
                );

                const data = await response.json();

                if (!response.ok) {

                    if (errorElement) {
                        errorElement.textContent =
                            data.error ||
                            "Invalid verification code.";

                        errorElement.hidden = false;
                    }

                    return;
                }

                

                
                if (data.status === "enabled") {

                    document
                        .getElementById("setup-code")
                        .value = "";

                    displayRecoveryCodes(
                            data.recovery_codes
                    );

                     showRecoveryCodes();
                    }

            } catch (error) {

                console.error(error);

                if (errorElement) {
                    errorElement.textContent =
                        "Unable to connect to the server.";

                    errorElement.hidden = false;
                }
            }
        }
    );
}



function showTwoFactorChallenge() {
    showTwoFactorScreen();
}

const twoFactorForm =
    document.getElementById("two-factor-form");

if (twoFactorForm) {
    twoFactorForm.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();

            const otp =
                document
                    .getElementById("two-factor-code")
                    .value
                    .trim();

            const errorElement =
                document.getElementById("two-factor-error");

            if (errorElement) {
                errorElement.textContent = "";
                errorElement.hidden = true;
            }

            if (!/^\d{6}$/.test(otp)) {
                if (errorElement) {
                    errorElement.textContent =
                        "Please enter a valid 6-digit code.";
                    errorElement.hidden = false;
                }
                return;
            }

            const formData = new FormData();
            formData.append("otp", otp);

            try {
                const response = await fetch(
                    "/2fa/challenge",
                    {
                        method: "POST",
                        body: formData
                    }
                );

                const data = await response.json();

                if (!response.ok) {
                    if (errorElement) {
                        errorElement.textContent =
                            data.error ||
                            "Invalid verification code.";
                        errorElement.hidden = false;
                    }
                    return;
                }

                if (data.status === "ok") {
                    twoFactorForm.reset();

                    alert(
                        "2FA verified. Login successful."
                    );

                    // Dashboard will be connected here later.
                }

            } catch (error) {
                console.error(error);

                if (errorElement) {
                    errorElement.textContent =
                        "Unable to connect to the ReAnchor server.";
                    errorElement.hidden = false;
                }
            }
        }
    );
}
const recoveryForm =
    document.getElementById("recovery-form");

if (recoveryForm) {

    recoveryForm.addEventListener(
        "submit",
        function (event) {

            event.preventDefault();

            const code =
                document
                    .getElementById("recovery-code")
                    .value
                    .trim();

            if (code.length !== 16) {

                alert(
                    "Please enter a valid 16-character recovery code."
                );

                return;
            }

            alert(
                "Recovery backend will be connected next."
            );
        }
    );
}