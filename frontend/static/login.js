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
          errorElement.textContent =
            "Authentication error: No token received";
          errorElement.classList.remove("hidden");
          return;
        }

        // Store the token in localStorage
        localStorage.setItem("accessToken", data.access_token);

        console.log(
          "Token saved to localStorage, length:",
          data.access_token.length
        );

        // Make the request to dashboard with Authorization header
        const dashboardResponse = await fetch("/dashboard", {
          headers: {
            Authorization: `Bearer ${data.access_token}`,
          },
        });

        // Check if we got HTML back (successful) or JSON (error)
        const contentType = dashboardResponse.headers.get("content-type");
        if (contentType && contentType.includes("text/html")) {
          // Got HTML - replace current page with it
          const html = await dashboardResponse.text();
          document.open();
          document.write(html);
          document.close();
          // Update URL without reloading
          window.history.pushState({}, "", "/dashboard");
        } else {
          // Error response
          errorElement.textContent =
            "Authentication failed. Please try again.";
          errorElement.classList.remove("hidden");
        }
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