class authManager {
    constructor(apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;

        this.access_token = localStorage.getItem("access_token");
        this.refresh_token = localStorage.getItem("refresh_token");

        if (this.access_token){
            this.isUserAuthenticated = true;
        }else{
            this.isUserAuthenticated = false;
        }
    }

    async register(first_name, last_name, email, password, password_confirm) {
        try {
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

            const response = await fetch(`${this.apiBaseUrl}register/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRFToken': csrfToken,
                },
                body: JSON.stringify({
                    first_name,
                    last_name,
                    email,
                    password,
                    password_confirm,
                }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || "Server responded with an error");
            }

            const data = await response.json();
            console.log(data.message);
        } catch (error) {
            console.log("Error occurred:", error.message);
        }
    }

    async login(email, password) {
        try {
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

            const response = await fetch(`${this.apiBaseUrl}login/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRFToken': csrfToken,
                },
                body: JSON.stringify({
                    email,
                    password,
                }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || "Server responded with an error");
            }else{
                const responseData = await response.json();
                console.log(responseData);
                const access_token = responseData.access_token;
                const refresh_token = responseData.refresh_token;
                localStorage.setItem("access_token", access_token);
                localStorage.setItem("refresh_token", refresh_token);
                console.log("Login Successful from javascript!");
            }
        } catch (error) {
            console.log("Error occurred:", error.message);
        }
    }

    decodeJWT(token) {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        return JSON.parse(jsonPayload);
    }

    isAccessTokenValid() {
        if (!this.access_token) {
            console.log("Access token is not present.");
            return false;
        }

        try {
            const decodedToken = this.decodeJWT(this.access_token);

            const currentTime = Math.floor(Date.now() / 1000);

            if (decodedToken.exp < currentTime) {
                console.log("Access token has expired.");
                return false;
            }

            console.log("Access token is valid.");
            return true;
        } catch (error) {
            console.error("Error decoding the access token:", error);
            return false;
        }
    }

    isRefreshTokenValid() {
        if (!this.refresh_token) {
            return false;
        }

        try {
            const decodedToken = this.decodeJWT(this.refresh_token);

            const currentTime = Math.floor(Date.now() / 1000);

            if (decodedToken.exp < currentTime) {
                console.log("Refresh token has expired.");
                return false;
            }

            console.log("Refresh token is valid.");
            return true;
        } catch (error) {
            console.error("Error decoding the refresh token:", error);
            return false;
        }
    }

    async refreshAccessToken() {
        if (!this.refresh_token) {
            console.log("No refresh token available.");
            return false;
        }

        try {
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

            const response = await fetch(`${this.apiBaseUrl}token/refresh/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRFToken': csrfToken,
                },
                body: JSON.stringify({
                    refresh_token: refresh_token
                })
            });

            if (!response.ok) {
                throw new Error('Failed to refresh access token');
            }

            const data = await response.json();

            // If new tokens are returned, update them in local storage
            if (data.access_token) {
                localStorage.setItem('access_token', data.access_token);
                // Optional: Update the refresh token if it's provided in the response
                if (data.refresh_token) {
                    localStorage.setItem('refresh_token', data.refresh_token);
                }
                console.log("Access token refreshed successfully.");
                return true;
            } else {
                console.error("No new access token received.");
                return false;
            }
        } catch (error) {
            console.error("Error refreshing access token:", error);
            return false;
        }
    }

    async isUserAuthenticated(){
        try{
            if (this.isAccessTokenValid()){
                return true;
            }else if (!this.isAccessTokenValid() && this.isRefreshTokenValid()){
                return refreshAccessToken();
            }else{
                return false;
            }
        }catch(error){
            console.error(error);
            return false;
        }
    }

    async logout() {
        try {
            localStorage.removeItem("access_token");
            localStorage.removeItem("refresh_token");
            console.log("You have been logged out.");
        } catch (error) {
            console.error("Logout failed:", error);
            alert("An error occurred during logout.");
        }
    }

    async makeProtectedRequest(url, data) {
        try {
            let access_token = localStorage.getItem("access_token");

            // Send the initial request with the access token
            const response = await axios.post(url, data, {
                headers: { Authorization: `Bearer ${access_token}` },
            });

            // Return the successful response data
            return response.data;

        } catch (error) {
            // Check if the error is due to an expired access token
            if (error.response && error.response.status === 401 && error.response.data.code === "token_not_valid") {
                console.log("Access token expired, attempting to refresh...");

                try {
                    // Get the refresh token from localStorage
                    const refresh_token = localStorage.getItem("refresh_token");

                    if (!refresh_token) {
                        alert("Session expired. Please log in again.");
                        window.location.href = "/login.html";
                        return;
                    }

                    // Request a new access token using the refresh token
                    const refreshResponse = await axios.post(`${this.apiBaseUrl}token/refresh/`, {
                        refresh: refresh_token,
                    });

                    const newAccessToken = refreshResponse.data.access;

                    // Update the access token in localStorage
                    localStorage.setItem("access_token", newAccessToken);

                    // Retry the original request with the new access token
                    const retryResponse = await axios.post(url, data, {
                        headers: { Authorization: `Bearer ${newAccessToken}` },
                    });

                    // Return the successful response data
                    return retryResponse.data;

                } catch (refreshError) {
                    console.error("Failed to refresh access token:", refreshError);
                    alert("Session expired. Please log in again.");
                    window.location.href = "/login.html";
                    return;
                }
            } else {
                // If the error is not related to token expiration, rethrow the error
                console.error("Request failed:", error);
                throw error;
            }
        }
    }
}
