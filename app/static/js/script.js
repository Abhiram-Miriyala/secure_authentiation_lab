/**
 * Secure Authentication Lab - Client-Side Interactive Helper Scripts
 * 
 * Provides interactive visual feedback for defensive controls:
 * 1. Real-time password strength meter & complexity checklist
 * 2. Password visibility toggles
 * 3. Client-side form sanity checks (server-side validation remains authoritative)
 */

document.addEventListener("DOMContentLoaded", () => {
    // =========================================================================
    // 1. Password Visibility Toggle
    // =========================================================================
    const toggleButtons = document.querySelectorAll(".toggle-password-btn");
    toggleButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");
            const input = document.getElementById(targetId);
            const icon = btn.querySelector("i");

            if (input && icon) {
                if (input.type === "password") {
                    input.type = "text";
                    icon.classList.remove("bi-eye");
                    icon.classList.add("bi-eye-slash");
                } else {
                    input.type = "password";
                    icon.classList.remove("bi-eye-slash");
                    icon.classList.add("bi-eye");
                }
            }
        });
    });

    // =========================================================================
    // 2. Real-Time Password Complexity Meter (Register View)
    // =========================================================================
    const passwordInput = document.getElementById("register-password");
    if (passwordInput) {
        const meterBar = document.getElementById("strength-bar");
        const meterText = document.getElementById("strength-text");

        const ruleLength = document.getElementById("rule-length");
        const ruleUpper = document.getElementById("rule-upper");
        const ruleLower = document.getElementById("rule-lower");
        const ruleDigit = document.getElementById("rule-digit");
        const ruleSpecial = document.getElementById("rule-special");

        const updateRule = (element, passed) => {
            if (!element) return;
            const icon = element.querySelector("i");
            if (passed) {
                element.classList.remove("text-secondary", "text-danger");
                element.classList.add("text-success");
                if (icon) {
                    icon.classList.remove("bi-circle");
                    icon.classList.add("bi-check-circle-fill");
                }
            } else {
                element.classList.remove("text-success");
                element.classList.add("text-secondary");
                if (icon) {
                    icon.classList.remove("bi-check-circle-fill");
                    icon.classList.add("bi-circle");
                }
            }
        };

        passwordInput.addEventListener("input", () => {
            const val = passwordInput.value;

            const hasLen = val.length >= 12;
            const hasUpper = /[A-Z]/.test(val);
            const hasLower = /[a-z]/.test(val);
            const hasDigit = /[0-9]/.test(val);
            const hasSpecial = /[!@#$%^&*(),.?":{}|<>\-_=+]/.test(val);

            updateRule(ruleLength, hasLen);
            updateRule(ruleUpper, hasUpper);
            updateRule(ruleLower, hasLower);
            updateRule(ruleDigit, hasDigit);
            updateRule(ruleSpecial, hasSpecial);

            let score = 0;
            if (val.length >= 8) score++;
            if (hasLen) score++;
            if (hasUpper) score++;
            if (hasLower) score++;
            if (hasDigit) score++;
            if (hasSpecial) score++;

            if (!meterBar || !meterText) return;

            if (val.length === 0) {
                meterBar.style.width = "0%";
                meterBar.className = "strength-meter-bar bg-secondary";
                meterText.textContent = "Enter password to evaluate";
                meterText.className = "small text-secondary";
            } else if (score <= 2) {
                meterBar.style.width = "25%";
                meterBar.className = "strength-meter-bar bg-danger";
                meterText.textContent = "Weak (Fails defensive security criteria)";
                meterText.className = "small text-danger";
            } else if (score <= 4) {
                meterBar.style.width = "65%";
                meterBar.className = "strength-meter-bar bg-warning";
                meterText.textContent = "Moderate (Meets partial requirements)";
                meterText.className = "small text-warning";
            } else if (score >= 5 && hasLen && hasUpper && hasLower && hasDigit && hasSpecial) {
                meterBar.style.width = "100%";
                meterBar.className = "strength-meter-bar bg-success";
                meterText.textContent = "Strong (Complies with defensive security standards)";
                meterText.className = "small text-success";
            }
        });
    }
});
