# Auth Service - Django Authentication System

A comprehensive user authentication service built with Django, featuring JWT authentication, PostgreSQL database, Redis caching, and password reset functionality.

## Features

- **User Registration & Login** with email as username
- **JWT Authentication** with access and refresh tokens
- **Password Reset** functionality using Redis for token storage
- **PostgreSQL** database integration
- **Redis** caching for password reset tokens
- **Rate Limiting** on authentication endpoints
- **API Documentation** with Swagger/OpenAPI
- **Docker** support for local development
- **Deployment** configurations for Railway and Render
- **Comprehensive Unit Tests**

## Tech Stack

- **Backend**: Django 5.0.1, Django REST Framework
- **Authentication**: JWT (Simple JWT)
- **Database**: PostgreSQL
- **Cache**: Redis
- **Documentation**: drf-yasg (Swagger/OpenAPI)
- **Deployment**: Docker, Railway, Render
- **Rate Limiting**: django-ratelimit

## Prerequisites

- Python 3.12+
- PostgreSQL 13+
- Redis 6+
- Docker (optional, for containerized development)

## Installation & Setup

### Local Development

1. **Clone the repository**

```bash
git clone <repository-url>
cd auth_service
```

2. **Create virtual environment**

```bash
python -m venv venv
source venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Environment Configuration**

```bash
cp .env.example .env

```

5. **Database Setup**

```bash

createdb auth_service_db

python manage.py migrate
```

6. **Create Superuser**

```bash
python manage.py createsuperuser
```

7. **Run Development Server**

```bash
python manage.py runserver
```

### Docker Development

1. **Build and run with Docker Compose**

```bash
docker-compose up --build
```

The entrypoint script will automatically:

- Wait for the database to be ready
- Run database migrations
- Collect static files
- Create a superuser (if ADMIN_EMAIL and ADMIN_PASSWORD are set)
- Start the development server

2. **Manual operations (if needed)**

```bash
docker-compose exec web python manage.py migrate

docker-compose exec web python manage.py createsuperuser

docker-compose exec web bash
```

## Environment Variables

Create a `.env` file in the project root with the following variables:

```env
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0

DATABASE_URL=postgresql://username:password@localhost:5432/auth_service_db

REDIS_URL=redis://localhost:6379/0

JWT_ACCESS_TOKEN_LIFETIME=60
JWT_REFRESH_TOKEN_LIFETIME=1440

EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
```

## API Documentation

Once the server is running, access the API documentation at:

- **Swagger UI**: http://localhost:8000/swagger/
- **ReDoc**: http://localhost:8000/redoc/
- **JSON Schema**: http://localhost:8000/swagger.json

## API Endpoints

### Health Check

- `GET /health/` - Service health status

### Authentication (API v1)

- `POST /api/v1/auth/register/` - User registration
- `POST /api/v1/auth/login/` - User login
- `POST /api/v1/auth/token/refresh/` - Refresh JWT token

### User Profile (API v1)

- `GET /api/v1/auth/profile/` - Get user profile

### Email Verification (API v1)

- `POST /api/v1/auth/verify-email/` - Verify email with token
- `POST /api/v1/auth/resend-verification/` - Resend verification email

### Password Reset (API v1)

- `POST /api/v1/auth/password-reset/` - Request password reset
- `POST /api/v1/auth/password-reset/confirm/` - Confirm password reset

## API Usage Examples

### Health Check

```bash
curl -X GET http://localhost:8000/health/
```

### User Registration

```bash
curl -X POST http://localhost:8000/api/v1/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "full_name": "John Doe",
    "password": "securepassword123",
    "password_confirm": "securepassword123"
  }'
```

### User Login

```bash
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### Access Protected Endpoint

```bash
curl -X GET http://localhost:8000/api/v1/auth/profile/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Password Reset Request

```bash
curl -X POST http://localhost:8000/api/v1/auth/password-reset/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

## Testing

Run the test suite:

```bash
python manage.py test

coverage run --source='.' manage.py test
coverage report
coverage html
```

## Deployment

### Production Deployment

The application includes several deployment scripts:

1. **Using the deployment script:**

```bash
python deploy.py
```

2. **Using the startup script:**

```bash
./start.sh
```

3. **Using the build script (for platforms like Render):**

```bash
./build.sh
```

### Platform-Specific Instructions

#### Render

1. Connect your GitHub repository
2. Set build command: `./build.sh`
3. Set start command: `./start.sh`
4. Add environment variables (see below)

#### Railway

1. Connect your GitHub repository
2. Set build command: `python deploy.py`
3. Add environment variables (see below)

#### Docker Production

```bash
docker build -t auth-service .
docker run -p 8000:8000 --env-file .env auth-service
```

#### Environment Variables for Production

```env
# Required
SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:password@host:port/database
REDIS_URL=redis://host:port/db
BREVO_API_KEY=your-brevo-api-key
FROM_EMAIL=your-email@domain.com

# Optional
DEBUG=False
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=secure-admin-password
CREATE_SUPERUSER=true
RUN_TESTS=false
```

## Security Features

- **Rate Limiting**: Prevents brute force attacks
- **JWT Tokens**: Secure stateless authentication
- **Password Validation**: Django's built-in password validators
- **CORS Configuration**: Controlled cross-origin requests
- **HTTPS Enforcement**: In production settings

## Troubleshooting

### Common Issues

#### Database Migration Errors

If you see `relation "auth_user" does not exist`:

1. **For local development:**

```bash
python manage.py migrate
```

2. **For Docker:**

```bash
docker-compose exec web python manage.py migrate
```

3. **For production deployment:**
   Ensure your deployment platform runs the build script or migrations:

- Render: Set build command to `./build.sh`
- Railway: Use `python deploy.py`
- Manual: Run `python manage.py migrate`

#### Redis Connection Issues

If you see Redis connection errors in local development:

- The app automatically falls back to local memory cache when Redis is unavailable
- For production, ensure REDIS_URL environment variable is set correctly

#### Environment Variables Not Loading

- Ensure `.env` file exists in the project root
- Check that environment variables are set in your deployment platform
- Verify variable names match exactly (case-sensitive)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authors

- **Barny Victor** - [GitHub](http://github.com/Barnyvic)
