# Biometric Authentication (WebAuthn)

A passwordless biometric authentication app using WebAuthn and Touch ID, built with Flask and PostgreSQL.

## Tech Stack

- **Backend:** Flask, Flask-SQLAlchemy, Flask-Session
- **Auth:** py_webauthn (WebAuthn / FIDO2)
- **Database:** PostgreSQL (via psycopg)
- **Frontend:** Vanilla HTML/JS

## Prerequisites

- Python 3.14+
- PostgreSQL running on localhost

## PostgreSQL Setup

### Install PostgreSQL (macOS)

```bash
brew install postgresql@17
brew services start postgresql@17
```

### Create the Database

```bash
psql postgres -c "CREATE DATABASE biometric_authn;"
```

### Connection Details

| Parameter | Value |
|-----------|-------|
| Host | `localhost` |
| Port | `5432` |
| Database | `biometric_authn` |
| URI | `postgresql+psycopg://localhost:5432/biometric_authn` |

The connection URI can be overridden via the `DATABASE_URL` environment variable:

```bash
export DATABASE_URL="postgresql+psycopg://user:password@localhost:5432/biometric_authn"
```

## Running the App

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

The app runs at **http://localhost:8081**.

## Database Schema

**users**

| Column | Type | Description |
|--------|------|-------------|
| email | VARCHAR(255) | Primary key |
| user_id | VARCHAR(255) | WebAuthn user ID |
| username | VARCHAR(255) | Display name |

**credentials**

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto) |
| email | VARCHAR(255) | FK to users |
| credential_id | TEXT | WebAuthn credential ID |
| credential_public_key | TEXT | Public key |
| sign_count | INTEGER | Signature counter |
| credential_type | VARCHAR(50) | Credential type |
| credential_device_type | VARCHAR(50) | Device type |
| credential_backed_up | BOOLEAN | Backup status |

Tables are auto-created on startup via `db.create_all()`.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serves the UI |
| POST | `/api/register-challenge` | Start registration |
| POST | `/api/register-verify` | Verify registration |
| POST | `/api/login-challenge` | Start login |
| POST | `/api/login-verify` | Verify login |
| POST | `/api/logout` | Logout |
| GET | `/api/user` | Get current user |
