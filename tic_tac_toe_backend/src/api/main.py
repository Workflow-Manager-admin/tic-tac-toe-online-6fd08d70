import os
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, ForeignKey
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session

# --- ENVIRONMENT VARIABLES ---
from dotenv import load_dotenv

load_dotenv()

POSTGRES_URL = os.getenv("POSTGRES_URL", "")
POSTGRES_USER = os.getenv("POSTGRES_USER", "")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "")
POSTGRES_DB = os.getenv("POSTGRES_DB", "")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

database_url = (
    POSTGRES_URL if POSTGRES_URL else
    f"postgresql+psycopg2://{POSTGRES_USER}:{POSTGRES_PASSWORD}@localhost:{POSTGRES_PORT}/{POSTGRES_DB}"
)

engine = create_engine(database_url, echo=False)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()

# --- PASSWORD CONTEXT ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# --- DATABASE MODELS ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scores = relationship("Score", uselist=False, back_populates="user")

class Game(Base):
    __tablename__ = "games"
    id = Column(Integer, primary_key=True)
    player_x = Column(Integer, ForeignKey('users.id'), nullable=True)
    player_o = Column(Integer, ForeignKey('users.id'), nullable=True)
    state = Column(String(10), nullable=False, default='WAITING') # WAITING, ACTIVE, FINISHED
    board_state = Column(String(32), nullable=False, default="         ") # 9 chars for 3x3 board
    winner = Column(Integer, ForeignKey('users.id'), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    moves = relationship("Move", back_populates="game")

class Move(Base):
    __tablename__ = "moves"
    id = Column(Integer, primary_key=True)
    game_id = Column(Integer, ForeignKey('games.id', ondelete="CASCADE"))
    player_id = Column(Integer, ForeignKey('users.id'))
    position = Column(Integer, nullable=False) # [0,8]
    move_order = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    game = relationship("Game", back_populates="moves")

class Score(Base):
    __tablename__ = "scores"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True)
    wins = Column(Integer, default=0)
    losses = Column(Integer, default=0)
    draws = Column(Integer, default=0)

    user = relationship("User", back_populates="scores")

# --- Pydantic Schemas ---

class UserBase(BaseModel):
    username: str = Field(..., max_length=50, description="Desired username")

class UserRegister(UserBase):
    password: str = Field(..., min_length=5, description="Password")

class UserOut(UserBase):
    id: int
    created_at: datetime
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class GameCreate(BaseModel):
    pass # just create, no input required

class GameJoin(BaseModel):
    game_id: int

class MoveIn(BaseModel):
    game_id: int
    position: int = Field(..., ge=0, le=8, description="Board position [0-8]")

class MoveOut(BaseModel):
    id: int
    game_id: int
    player_id: int
    position: int
    move_order: int
    created_at: datetime
    class Config:
        orm_mode = True

class GameOut(BaseModel):
    id: int
    player_x: Optional[int]
    player_o: Optional[int]
    state: str
    board_state: str
    winner: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class ScoreOut(BaseModel):
    wins: int
    losses: int
    draws: int

    class Config:
        orm_mode = True

class GameHistory(BaseModel):
    game_id: int
    opponent: str
    result: str
    created_at: datetime

# --- FASTAPI APP ---

app = FastAPI(
    title="Tic Tac Toe Backend",
    description="REST API backend for Tic Tac Toe Online",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User authentication"},
        {"name": "game", "description": "Game creation, joining, moves"},
        {"name": "score", "description": "Score and history"},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- AUTH UTILS ---

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generate JWT token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter_by(username=username).first()

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = get_user_by_username(db, username)
    if user and verify_password(password, user.password_hash):
        return user
    return None

# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Get user for current token for auth-protected endpoints"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# === API ROUTES ===

@app.get("/", tags=["health"])
def health_check():
    """Health check route"""
    return {"message": "Healthy"}

# --- USER REGISTRATION & LOGIN ---

# PUBLIC_INTERFACE
@app.post("/register", response_model=UserOut, tags=["auth"])
def register(user: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user.
    """
    db_user = get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    user_obj = User(
        username=user.username,
        password_hash=get_password_hash(user.password)
    )
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    # Create score row for the user
    score_obj = Score(user_id=user_obj.id)
    db.add(score_obj)
    db.commit()
    return user_obj

# PUBLIC_INTERFACE
@app.post("/token", response_model=Token, tags=["auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    User login using OAuth2PasswordRequestForm for JWT Bearer.
    Returns access token on success.
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- GAME LOGIC ---

def game_board_from_state(state: str) -> List[List[str]]:
    assert len(state) == 9
    return [[state[i * 3 + j] for j in range(3)] for i in range(3)]

def game_state_from_board(board: List[List[str]]) -> str:
    return "".join(board[i][j] for i in range(3) for j in range(3))

def current_turn(state: str) -> str:
    # 'X' goes first, alternate turns; if counts equal X's turn, else O's
    x_count = state.count('X')
    o_count = state.count('O')
    return 'X' if x_count <= o_count else 'O'

def check_game_outcome(state: str) -> Optional[str]:
    "Returns 'X' or 'O' when someone won, 'DRAW' for draw, or None for ongoing"
    board = game_board_from_state(state)
    lines = []
    lines.extend(board)
    lines.extend([[board[i][j] for i in range(3)] for j in range(3)]) # columns
    lines.append([board[i][i] for i in range(3)])
    lines.append([board[i][2 - i] for i in range(3)])
    for line in lines:
        if line == ['X'] * 3:
            return "X"
        if line == ['O'] * 3:
            return "O"
    if " " not in state:
        return "DRAW"
    return None

# PUBLIC_INTERFACE
@app.post("/games/", response_model=GameOut, tags=["game"])
def create_game(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Create a new game. The creator is assigned as X.
    """
    game = Game(
        player_x=current_user.id,
        player_o=None,
        state="WAITING",
        board_state=" " * 9
    )
    db.add(game)
    db.commit()
    db.refresh(game)
    return game

# PUBLIC_INTERFACE
@app.post("/games/{game_id}/join", response_model=GameOut, tags=["game"])
def join_game(game_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Join a game as player O if there is space.
    """
    game: Game = db.query(Game).filter(Game.id == game_id).first()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    if game.player_o is not None:
        raise HTTPException(status_code=403, detail="Game already full")
    if game.player_x == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot join your own game")
    game.player_o = current_user.id
    game.state = "ACTIVE"
    db.commit()
    db.refresh(game)
    return game

# PUBLIC_INTERFACE
@app.get("/games/{game_id}", response_model=GameOut, tags=["game"])
def get_game(game_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Retrieve current state of a game.
    """
    game: Game = db.query(Game).filter(Game.id == game_id).first()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    return game

# PUBLIC_INTERFACE
@app.get("/games/", response_model=List[GameOut], tags=["game"])
def list_games(state: Optional[str] = None, skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    """
    List games, optionally filtered by state.
    """
    query = db.query(Game)
    if state:
        query = query.filter(Game.state == state)
    query = query.order_by(Game.updated_at.desc()).offset(skip).limit(limit)
    return query.all()

# PUBLIC_INTERFACE
@app.post("/games/{game_id}/move", response_model=MoveOut, tags=["game"])
def make_move(game_id: int, move: MoveIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Make a move in an existing game if allowed.
    """
    game: Game = db.query(Game).filter(Game.id == game_id).first()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    if game.state != "ACTIVE":
        raise HTTPException(status_code=400, detail="Game not in active state")
    if current_user.id not in [game.player_x, game.player_o]:
        raise HTTPException(status_code=403, detail="Not a participant")
    pos = move.position
    board = list(game.board_state)
    if not (0 <= pos < 9) or board[pos] != " ":
        raise HTTPException(status_code=400, detail="Invalid move position")
    # Check correct turn
    if current_turn(game.board_state) != ('X' if current_user.id == game.player_x else 'O'):
        raise HTTPException(status_code=400, detail="Not your turn")
    board[pos] = 'X' if current_user.id == game.player_x else 'O'
    game.board_state = "".join(board)
    # Find the number of previous moves
    prev_moves = db.query(Move).filter(Move.game_id == game_id).count()
    move_obj = Move(
        game_id=game_id,
        player_id=current_user.id,
        position=pos,
        move_order=prev_moves + 1
    )
    game.updated_at = datetime.utcnow()
    # Check for a winner
    outcome = check_game_outcome(game.board_state)
    if outcome == "X":
        game.state = "FINISHED"
        game.winner = game.player_x
        update_scores(db, game.player_x, game.player_o, "X")
    elif outcome == "O":
        game.state = "FINISHED"
        game.winner = game.player_o
        update_scores(db, game.player_x, game.player_o, "O")
    elif outcome == "DRAW":
        game.state = "FINISHED"
        game.winner = None
        update_scores(db, game.player_x, game.player_o, "DRAW")
    db.add(move_obj)
    db.commit()
    db.refresh(move_obj)
    db.refresh(game)
    return move_obj

def update_scores(db: Session, player_x_id: int, player_o_id: int, outcome: str):
    # outcome: "X", "O", "DRAW"
    score_x = db.query(Score).filter(Score.user_id == player_x_id).first()
    score_o = db.query(Score).filter(Score.user_id == player_o_id).first()
    if not score_x or not score_o:
        return
    if outcome == "X":
        score_x.wins += 1
        score_o.losses += 1
    elif outcome == "O":
        score_o.wins += 1
        score_x.losses += 1
    elif outcome == "DRAW":
        score_x.draws += 1
        score_o.draws += 1
    db.commit()

# PUBLIC_INTERFACE
@app.get("/games/{game_id}/moves", response_model=List[MoveOut], tags=["game"])
def get_moves(game_id: int, db: Session = Depends(get_db)):
    """
    Return moves for a game, ordered by move_order.
    """
    moves = db.query(Move).filter(Move.game_id == game_id).order_by(Move.move_order.asc()).all()
    return moves

# --- SCORE & HISTORY ---

# PUBLIC_INTERFACE
@app.get("/score/", response_model=ScoreOut, tags=["score"])
def get_my_score(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Get current user's score card.
    """
    score = db.query(Score).filter(Score.user_id == current_user.id).first()
    if not score:
        raise HTTPException(status_code=404, detail="Score not found")
    return score

# PUBLIC_INTERFACE
@app.get("/history/", response_model=List[GameHistory], tags=["score"])
def get_my_game_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Retrieve game history for the current user.
    """
    games = db.query(Game).filter(
        (Game.player_x == current_user.id) | (Game.player_o == current_user.id)
    ).order_by(Game.created_at.desc()).all()
    history = []
    for game in games:
        opponent_id = game.player_o if game.player_x == current_user.id else game.player_x
        # Handle friends-and-foes in solo/training games: sometimes, player_o or player_x can be None
        opponent_user = db.query(User).filter(User.id == opponent_id).first() if opponent_id else None
        opponent = opponent_user.username if opponent_user else "N/A"
        if game.state != "FINISHED":
            result = "IN_PROGRESS"
        elif game.winner is None:
            result = "DRAW"
        elif game.winner == current_user.id:
            result = "WIN"
        else:
            result = "LOSS"
        history.append(GameHistory(
            game_id=game.id,
            opponent=opponent,
            result=result,
            created_at=game.created_at
        ))
    return history

# --- INIT DATABASE TABLES IF NEEDED ---
@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
