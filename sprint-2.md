# **Sprint 2: User Login System**

## **Backlog Tasks**

~~1. Create a login form with:~~

- Username/Email field
- Password field
- Sign-In button.

~~2. Design a responsive, mobile-friendly login page.~~

~~3. Create a backend route for `/login`:~~

- Retrieve user information and compare hashed passwords.
- Handle session creation to manage user authentication:
  - Use `Flask.session` to store user information (e.g., username, role) securely.
  - Set session expiration for added security.

~~4. Implement a `/logout` route to clear session data and log the user out.~~

~~5. Display error messages for invalid login attempts and unsuccessful authentication.~~

## **Increment**

- Developed a **login page** with form fields for username/email and password.
- Integrated Google Sign-In functionality.
- Implemented **secure session-based authentication**:
  - User sessions are initiated upon successful login.
  - Stored user role and identification for role-based redirection.
  - Added session timeout configuration.
- Handled role-based redirection for users and admins.

## **Review**

- **Session Management**:  
  Confirmed that user sessions are securely created and cleared on logout.  
  Verified session timeout works as expected.
- **Error Handling**:  
  Tested invalid login attempts and ensured appropriate error messages are displayed.
- **Security**:  
  Checked secure storage of session data without sensitive information being exposed.
