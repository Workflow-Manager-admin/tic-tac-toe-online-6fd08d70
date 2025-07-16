# Use official PostgreSQL image
FROM postgres:15

# Allow using .env for build-time variable expansion (optional)
ENV POSTGRES_USER=${POSTGRES_USER:-tictactoe_user}
ENV POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-changeme}
ENV POSTGRES_DB=${POSTGRES_DB:-tictactoe_db}

# Add schema to initialize
COPY schema.sql /docker-entrypoint-initdb.d/
