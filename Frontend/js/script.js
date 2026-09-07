/* =========================
   SCREEN MANAGEMENT
========================= */

function hideAllScreens() {
    const screens = document.querySelectorAll(".screen");

    screens.forEach(function (screen) {
        screen.classList.remove("active");
    });
}


function showLogin() {
    hideAllScreens();

    document
        .getElementById("login-screen")
        .classList.add("active");
}


function showRegister() {
    hideAllScreens();

    document
        .getElementById("register-screen")
        .classList.add("active");
}


function showRecovery() {
    hideAllScreens();

    document
        .getElementById("recovery-screen")
        .classList.add("active");
}


/* =========================
   LOGO LINKS
========================= */

document.querySelectorAll(".logo-link").forEach(function (link) {

    link.addEventListener("click", function (event) {

        event.preventDefault();

        showLogin();
    });

});


/* =========================
   REGISTER VALIDATION
========================= */

const registerForm =
    document.getElementById("register-form");

if (registerForm) {

    registerForm.addEventListener("submit", function (event) {

        const password =
            document.getElementById("register-password").value;

        const confirmation =
            document.getElementById(
                "register-password-confirmation"
            ).value;

        if (password !== confirmation) {

            event.preventDefault();

            alert("Passwords do not match.");

            return;
        }

    });

}


/* =========================
   RECOVERY FORM
========================= */

const recoveryForm =
    document.getElementById("recovery-form");

if (recoveryForm) {

    recoveryForm.addEventListener("submit", function (event) {

        event.preventDefault();

        const code =
            document.getElementById("recovery-code").value.trim();

        if (code.length !== 16) {

            alert(
                "Please enter a valid 16-character recovery code."
            );

            return;
        }

        /*
         * Backend recovery verification will be connected here.
         *
         * Example future request:
         *
         * fetch("/recover", {
         *     method: "POST",
         *     headers: {
         *         "Content-Type": "application/json"
         *     },
         *     body: JSON.stringify({
         *         recovery_code: code
         *     })
         * });
         */

        alert(
            "Recovery code received. Backend verification will be connected next."
        );

    });

}