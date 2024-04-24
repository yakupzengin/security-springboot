## Spring Boot JWT Authentication Example

This project provides an example of implementing JWT (JSON Web Token) authentication in a Spring Boot application. With JWT authentication, users can register, authenticate, and access protected resources using JSON Web Tokens.

### Features

- User registration
- User authentication
- JWT token generation and validation
- Role-based access control (RBAC)
- Stateless authentication

### Getting Started

1. Clone the project:

   ```bash
   git clone https://github.com/your-username/spring-boot-jwt-authentication.git
2. Navigate to the project directory:
   ```bash
   cd spring-boot-jwt-authentication
3. Compile and run the application:
   ```bash
   ./mvnw spring-boot:run
4. Access the application at http://localhost:8080.


## Endpoints

### Registration

- **URL:** `/api/v1/auth/register`
- **Method:** `POST`
- **Request Body (Istek Govdesi):**

```json
{
  "firstname": "John",
  "lastname": "Doe",
  "email": "john@example.com",
  "password": "password"
}
