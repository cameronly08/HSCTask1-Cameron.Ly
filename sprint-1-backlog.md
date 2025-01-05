# **Sprint 1: User Sign-Up System**

## **Backlog Tasks**

~~1. Create a sign-up form with the following fields:~~

- Username
- Email
- Password
- Role (user/admin)

~~2. Implement front-end validation for:~~

- Password length (8-12 characters)
- At least one uppercase, one lowercase, and one special character.

~~3. Integrate a ** Sign-In** button.~~

~~4. Design a responsive UI with mobile-friendly layout.~~

~~5. Create a backend route for `/signup`:~~

- Hash passwords using `bcrypt` or `passlib`.

- Validate username uniqueness and email format.
- Store user roles securely in a database or structured data.

~~6. Implement input sanitization for security.~~

## **Increment**

- Developed a **user-friendly sign-up page** with a **Google Sign-In** button.
- Implemented password requirements and validation.
- Passwords are securely hashed before storage.
- Role selection is functional and ready for further role-based access control.

## **Review**

- **Form Validation**:  
  Verified that password constraints and validation logic work as expected.
- **Security**:  
  Checked that passwords are hashed and stored securely.
- **UI**:  
  The sign-up page is mobile-friendly and includes Sign-In button.
