// login.py
document
  .getElementById("login-btn")
  .addEventListener("click", async function () {
    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;
    const errorElement = document.getElementById("login-error");

    errorElement.classList.add("hidden");

    try {
      const response = await fetch("/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (response.ok) {
        // Check if access_token exists in the response
        if (!data.access_token) {
            console.error("No access token in response:", data);
            errorElement.textContent = "Authentication error: No token received";
            errorElement.classList.remove("hidden");
            return;
        }
        // Store the token in cookie using the correct property name
        document.cookie = `access_token_cookie=${data.access_token}; path=/; max-age=3600; SameSite=Strict`;  
        localStorage.setItem('wids_username', username);
    
        // Redirect to dashboard
        window.location.href = '/dashboard';
    } else {
        errorElement.textContent = data.msg || "Login failed";
        errorElement.classList.remove("hidden");
      }
    } catch (error) {
      errorElement.textContent = "An error occurred. Please try again.";
      errorElement.classList.remove("hidden");
      console.error("Login error:", error);
    }
  });