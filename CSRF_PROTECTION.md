# CSRF Protection Implementation

## Overview
This application now implements Cross-Site Request Forgery (CSRF) protection to prevent unauthorized state-changing operations.

## How It Works

### Server-Side
1. **Token Generation**: When a user visits the application, a CSRF token is automatically generated and stored in a cookie named `XSRF-TOKEN`.
2. **Token Validation**: All state-changing HTTP methods (POST, PUT, PATCH, DELETE) require a valid CSRF token to be present in the request.
3. **Token Verification**: The server validates that the token in the cookie matches the token provided in the request header or body.

### Client-Side Integration

#### Getting the CSRF Token
The CSRF token is automatically set in the `XSRF-TOKEN` cookie. You can:

1. **Read from cookie**: Extract the token from the `XSRF-TOKEN` cookie
2. **API endpoint**: Call `GET /rest/csrf-token` to retrieve the current token:
   ```javascript
   const response = await fetch('/rest/csrf-token')
   const { token } = await response.json()
   ```

#### Including the Token in Requests

For all state-changing requests (POST, PUT, PATCH, DELETE), include the CSRF token in one of these ways:

##### Option 1: Request Header (Recommended)
```javascript
fetch('/api/some-endpoint', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-XSRF-TOKEN': getCsrfTokenFromCookie()
  },
  body: JSON.stringify(data)
})
```

##### Option 2: Request Body
```javascript
fetch('/api/some-endpoint', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    ...data,
    _csrf: getCsrfTokenFromCookie()
  })
})
```

#### Helper Function to Extract Token from Cookie
```javascript
function getCsrfTokenFromCookie() {
  const cookieValue = document.cookie
    .split('; ')
    .find(row => row.startsWith('XSRF-TOKEN='))
  return cookieValue ? cookieValue.split('=')[1] : null
}
```

## Security Features

1. **SameSite Cookie**: The CSRF token cookie has `SameSite=strict` attribute to prevent cross-site attacks
2. **Timing-Safe Comparison**: Token validation uses constant-time comparison to prevent timing attacks
3. **Automatic Token Rotation**: Tokens are automatically regenerated when missing
4. **HTTPOnly=false**: The cookie is accessible to JavaScript (required for client-side reading)

## Error Responses

If CSRF validation fails, the server will respond with:
- **Status Code**: 403 Forbidden
- **Response Body**: 
  - `{ "error": "CSRF token missing in cookie" }` - Cookie not found
  - `{ "error": "CSRF token missing in request" }` - Token not provided in request
  - `{ "error": "Invalid CSRF token" }` - Token mismatch

## Testing

To test CSRF protection:

1. **Valid Request**: Include the CSRF token from the cookie in your request
2. **Invalid Token**: Try using a different or missing token - should get 403 error
3. **Cross-Origin Request**: Attempt a request from a different origin - should fail due to cookie policy

## Migration Guide for Existing Code

Update all AJAX/fetch calls that perform state-changing operations to include the CSRF token:

```javascript
// Before
fetch('/profile', {
  method: 'POST',
  body: formData
})

// After
fetch('/profile', {
  method: 'POST',
  headers: {
    'X-XSRF-TOKEN': getCsrfTokenFromCookie()
  },
  body: formData
})
```

## References
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Double Submit Cookie Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie)
