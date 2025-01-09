# Sprint 4: Development & Feature Enhancements

## Features to be Implemented:

- **Email Verification**: (Scrapped)
  - Implement registration email verification with a unique token.
  - Users must verify their email before logging in.
- **Password Recovery**:

  - Users can reset passwords using a link sent to their email.
  - Implement token-based password reset with expiration.

- ~~**Log Editing & Deleting (with Constraints)**:~~
  - Allow users to edit or delete their logs.
  - Constraints:
    - Only the log creator can edit or delete their logs.
    - Logs that are approved/archived cannot be edited or deleted.
  - Show timestamps for when logs are last edited.

## Sprint Increment:

### Email Verification: (too difficult, couldn't get it working)

- Updated registration to send a verification link.
- Generated unique tokens for email verification.
- Created route to handle email verification upon user click.

### Password Recovery:

- "Forgot Password" page for email entry.
- Password reset token generation with expiration time.
- Users receive a reset link via email.
- Implemented secure password reset form.

### Log Editing & Deleting:

- Added functionality to allow editing/deleting logs by creators only.
- Prevented editing/deleting of approved/archived logs.
- Timestamps added for log edits.
- Error handling for unauthorized access.

## Sprint Review:

- **Completed Features**:

  - password recovery, and log editing/deleting with constraints implemented.
  - Features tested for functionality and security.

- **Testing & QA**:

  - Password reset process tested for token expiration and secure handling.
  - Log editing/deleting tested for permission constraints.

- **Challenges**:
  - Configuring email service proved way too conflicting, therefore scrapped in order to meet the due date.
  - Token expiry handling and UI updates took longer than expected.
