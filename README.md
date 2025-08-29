# Auth Service - Django Authentication System

A comprehensive user authentication service built with Django, featuring JWT authentication, PostgreSQL database, Redis caching, and password reset functionality.

##  Features

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

##  Tech Stack

- **Backend**: Django 5.0.1, Django REST Framework
- **Authentication**: JWT (Simple JWT)
- **Database**: PostgreSQL
- **Cache**: Redis
- **Documentation**: drf-yasg (Swagger/OpenAPI)
- **Deployment**: Docker, Railway, Render
- **Rate Limiting**: django-ratelimit

##   Prerequisites

- Python 3.12+
- PostgreSQL 13+
- Redis 6+
- Docker (optional, for containerized development)

##  Installation & Setup

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

2. **Run migrations in container**
```bash
docker-compose exec web python manage.py migrate
```

3. **Create superuser in container**
```bash
docker-compose exec web python manage.py createsuperuser
```

##  Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0

# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/auth_service_db

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# JWT Settings
JWT_ACCESS_TOKEN_LIFETIME=60
JWT_REFRESH_TOKEN_LIFETIME=1440

# Email Settings (for password reset)
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
```

##  API Documentation

Once the server is running, access the API documentation at:

- **Swagger UI**: http://localhost:8000/swagger/
- **ReDoc**: http://localhost:8000/redoc/
- **JSON Schema**: http://localhost:8000/swagger.json

##  API Endpoints

### Authentication
- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `POST /api/auth/token/refresh/` - Refresh JWT token
- `POST /api/auth/token/verify/` - Verify JWT token

### User Profile
- `GET /api/auth/profile/` - Get user profile
- `PATCH /api/auth/profile/` - Update user profile

### Password Reset
- `POST /api/auth/password-reset/` - Request password reset
- `POST /api/auth/password-reset/confirm/` - Confirm password reset

##  API Usage Examples

### User Registration
```bash
curl -X POST http://localhost:8000/api/auth/register/ \
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
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### Access Protected Endpoint
```bash
curl -X GET http://localhost:8000/api/auth/profile/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Password Reset Request
```bash
curl -X POST http://localhost:8000/api/auth/password-reset/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

##  Testing

Run the test suite:

```bash
python manage.py test

coverage run --source='.' manage.py test
coverage report
coverage html
```

##  Deployment

### Railway Deployment

1. **Connect your GitHub repository to Railway**
2. **Set environment variables in Railway dashboard**
3. **Deploy automatically on push to main branch**

### Render Deployment

1. **Connect your GitHub repository to Render**
2. **Use the provided `render.yaml` configuration**
3. **Set environment variables in Render dashboard**

### Environment Variables for Production

```env
DEBUG=False
SECRET_KEY=your-production-secret-key
DATABASE_URL=your-production-database-url
REDIS_URL=your-production-redis-url
ALLOWED_HOSTS=your-domain.com
```

##  Security Features

- **Rate Limiting**: Prevents brute force attacks
- **JWT Tokens**: Secure stateless authentication
- **Password Validation**: Django's built-in password validators
- **CORS Configuration**: Controlled cross-origin requests
- **HTTPS Enforcement**: In production settings

##  Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Authors

- **Barny Victor** - *Initial work* - [YourGitHub](http://github.com/Barnyvic)

##  Acknowledgments

- Django REST Framework team
- Simple JWT library contributors
- PostgreSQL and Redis communities
