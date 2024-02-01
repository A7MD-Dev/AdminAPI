**ADMIN API**

**Project Overview**

This project is a Spring Boot REST API that implements JWT-based authentication to secure its resources. It features:

- User management endpoints (list and add new users).
- Admin login endpoint with JWT token generation.
- JWT validation filter for protected endpoints.
- Automatic logout after adding a new user account.

**Technologies Used**

- Java 1.8 or higher
- Spring Boot
- H2 Database
- Maven
- Spring Security
- JWT (io.jsonwebtoken)

**Setup and Configuration**

1. Clone or download the project.
2. Import it into your preferred IDE.
3. Ensure you have Java 1.8 or higher and Maven installed.
4. Update the secret key in `JwtAuthenticationFilter` with a secure value (not hardcoded).
5. Configure the database connection details if needed.
6. Run the project using `mvn spring-boot:run`.

**Endpoints**

### Admin Endpoints

- **Admin/Login (POST):**
    - Authenticates an admin user.
    - Requires username and password in request body.
    - Returns a JWT token in the `Authorization` header upon success.

### User Endpoints (Secured)

- **User/list (GET):**
    - Lists existing users (requires valid JWT in header).
- **User/Add new account (POST):**
    - Adds a new user account (requires valid JWT in header).
    - Invalidates the current JWT and logs out the admin user after successful creation.

**Authentication Flow**

1. Admin calls `Admin/Login` with credentials.
2. Upon successful authentication, a JWT token is generated and returned.
3. Admin includes the JWT token in the `Authorization` header of subsequent requests.
4. `JwtAuthenticationFilter` intercepts requests to protected endpoints.
5. Filter validates the JWT token using the secret key.
6. If valid, the authenticated user is set in the security context.
7. Access to protected resources is granted.

**Security Considerations**

- **Secure secret key storage:** Use a configuration file or environment variable, not hardcoded.
- **Input validation:** Validate user input to prevent vulnerabilities.
- **Exception handling:** Handle authentication exceptions gracefully.
- **Password hashing:** Hash user passwords using strong algorithms.
- **CSRF protection:** Consider implementing CSRF protection mechanisms.
- **Thorough testing:** Use Postman or similar tools to test authentication and authorization flows.

**Additional Notes**

- All endpoints (except `Admin/Login`) are secured with JWT.
- No sensitive data is stored in the JWT body.
