# Location Punch Attendance System

A professional web application for tracking employee attendance using geolocation-based punch in/out functionality.

## Project Structure

```
onecreditgeolocation/
├── backend/          # Server-side code
│   ├── server.js     # Express server with API endpoints
│   ├── package.json  # Backend dependencies
│   └── .gitignore    # Git ignore for backend
├── frontend/         # Client-side code
│   ├── index.html    # Main attendance interface
│   ├── login.html    # User login page
│   ├── signup.html   # User registration page
│   ├── admin.html    # Admin attendance viewer
│   ├── welcome.html  # Welcome/landing page
│   └── landing.html  # Alternative landing page
└── README.md         # This file
```

## Features

- **User Authentication**: Secure signup and login with password hashing
- **Geolocation Tracking**: Location-based attendance punching with geofence validation
- **Admin Dashboard**: View all attendance records
- **Session Management**: Secure session-based authentication
- **Responsive Design**: Modern UI with dark/light mode toggle

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (running on localhost:27017)
- Modern web browser with geolocation support

## Installation

1. Clone the repository
2. Navigate to the backend directory:
   ```bash
   cd backend
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start MongoDB service
5. Start the server:
   ```bash
   npm start
   ```

## Usage

1. Open your browser and go to `http://localhost:3000/welcome.html`
2. Sign up for a new account or login
3. Use the punch in/out buttons to record attendance
4. Admin users can access `http://localhost:3000/admin.html` to view all records

## API Endpoints

- `POST /api/signup` - User registration
- `POST /api/login` - User authentication
- `POST /api/punch-in` - Record punch in
- `POST /api/punch-out` - Record punch out
- `GET /api/punches` - Get user's attendance records
- `GET /api/admin/attendance` - Get all attendance records (admin only)

## Security

- Passwords are hashed using bcrypt
- JWT tokens for admin authentication
- Session-based authentication for regular users
- Geofence validation ensures attendance is recorded within office premises

## Development

- Backend: Node.js with Express
- Database: MongoDB with Mongoose
- Frontend: Vanilla JavaScript and HTML/CSS

## License

ISC