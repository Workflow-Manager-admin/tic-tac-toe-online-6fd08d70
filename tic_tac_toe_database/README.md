# Tic Tac Toe Database

This is the PostgreSQL database service for the Tic Tac Toe Online application. It manages user data, game sessions, and persistent score tracking for all players.

## Getting Started

1. Ensure you have Docker installed (recommended for running postgres).
2. Copy `.env.example` to `.env` and fill in your desired credentials.
3. If not using Docker, ensure a local PostgreSQL instance is running and credentials match your `.env`.

### Database Schema

- **users**
  - id (serial PK)
  - username (unique, varchar)
  - password_hash (varchar)
  - created_at (timestamp)

- **games**
  - id (serial PK)
  - player_x (FK -> users.id)
  - player_o (FK -> users.id)
  - state (varchar, e.g. 'WAITING', 'ACTIVE', 'FINISHED')
  - board_state (varchar, e.g. JSON or string for board)
  - winner (nullable FK -> users.id)
  - created_at (timestamp)
  - updated_at (timestamp)

- **moves**
  - id (serial PK)
  - game_id (FK -> games.id)
  - player_id (FK -> users.id)
  - position (int)
  - move_order (int)
  - created_at (timestamp)

- **scores**
  - id (serial PK)
  - user_id (FK -> users.id)
  - wins (int)
  - losses (int)
  - draws (int)

### Running Migrations

```bash
psql -U $POSTGRES_USER -d $POSTGRES_DB -f schema.sql
```

Or if using Docker Compose:
```bash
docker compose up -d
```

## Environment Variables

See `.env.example` for necessary variables.

## Notes

- The backend (`tic_tac_toe_backend`) expects the following env vars to connect: `POSTGRES_URL`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_PORT`.
- Adjust connection details as required for your deployment environment.

