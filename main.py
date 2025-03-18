from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import uvicorn
from typing import Dict, List

# Конфигурация JWT
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Настройка базы данных (SQLite)
DATABASE_URL = "sqlite:///./messenger.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Базовая модель SQLAlchemy
Base = declarative_base()

# Модель пользователя
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

# Модель сообщения
class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, index=True)
    receiver = Column(String, index=True)
    message = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_delivered = Column(Boolean, default=False)  # Поле для отслеживания доставки

# Создание таблиц в базе данных
Base.metadata.create_all(bind=engine)

# Инициализация FastAPI
app = FastAPI(
    title="Локальный мессенджер",
    description="API для локального мессенджера с использованием FastAPI и WebSocket. Подходит для разработки мобильных приложений.",
    version="1.0.0",
    license_info={
        "name": "MIT",
    },
)

# Контекст для хэширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Модель для регистрации
class UserRegister(BaseModel):
    username: str = Field(..., description="Имя пользователя", example="user1")
    password: str = Field(..., description="Пароль", example="password123")

# Модель для токена
class Token(BaseModel):
    access_token: str = Field(..., description="JWT токен", example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    token_type: str = Field(..., description="Тип токена", example="bearer")

# Модель для данных в токене
class TokenData(BaseModel):
    username: str | None = Field(None, description="Имя пользователя")

# Функция для хэширования пароля
def get_password_hash(password):
    return pwd_context.hash(password)

# Функция для проверки пароля
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Функция для аутентификации пользователя
def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

# Функция для создания JWT токена
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Зависимость для получения текущего пользователя
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Зависимость для получения сессии базы данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось подтвердить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

# Хранение активных WebSocket-соединений
active_connections: Dict[str, WebSocket] = {}

# Эндпоинт для регистрации
@app.post(
    "/register/",
    summary="Регистрация пользователя",
    description="Регистрация нового пользователя в системе.",
    response_description="Статус регистрации",
)
async def register(user: UserRegister, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Имя пользователя уже занято")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"status": "Пользователь зарегистрирован"}

# Эндпоинт для авторизации и получения токена
@app.post(
    "/token/",
    response_model=Token,
    summary="Авторизация",
    description="Авторизация пользователя и получение JWT токена.",
)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Создаем токен
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Эндпоинт для WebSocket-соединения
@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str, db: Session = Depends(get_db)):
    # Подключаем WebSocket
    await websocket.accept()
    
    # Сохраняем соединение в словаре активных соединений
    active_connections[username] = websocket

    try:
        while True:
            # Ожидаем сообщения от клиента (если нужно)
            data = await websocket.receive_text()
            # Можно добавить логику обработки входящих сообщений
    except WebSocketDisconnect:
        # Удаляем соединение при отключении
        del active_connections[username]

# Эндпоинт для отправки сообщения через WebSocket
@app.post(
    "/send_message/",
    summary="Отправка сообщения через WebSocket",
    description="Отправка сообщения другому пользователю через WebSocket.",
)
async def send_message(receiver_username: str, message: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Находим получателя в базе данных
    receiver = db.query(User).filter(User.username == receiver_username).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Получатель не найден")

    # Сохраняем сообщение в базе данных
    new_message = Message(sender=current_user.username, receiver=receiver.username, message=message)
    db.add(new_message)
    db.commit()

    # Если получатель онлайн, отправляем сообщение через WebSocket
    if receiver_username in active_connections:
        receiver_websocket = active_connections[receiver_username]
        try:
            await receiver_websocket.send_text(f"{current_user.username}: {message}")
            # Помечаем сообщение как доставленное
            new_message.is_delivered = True
            db.commit()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Не удалось отправить сообщение: {str(e)}")

    return {"status": "Сообщение отправлено", "receiver": receiver.username}

# Эндпоинт для получения недоставленных сообщений
@app.get(
    "/get_undelivered_messages/",
    summary="Получение недоставленных сообщений",
    description="Возвращает все сообщения, которые не были доставлены пользователю, пока он был оффлайн.",
)
async def get_undelivered_messages(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Находим все сообщения, адресованные текущему пользователю, которые не были доставлены
    undelivered_messages = db.query(Message).filter(
        Message.receiver == current_user.username,
        Message.is_delivered == False
    ).all()

    # Помечаем сообщения как доставленные
    for message in undelivered_messages:
        message.is_delivered = True
    db.commit()

    # Возвращаем сообщения
    return {"messages": [
        {"sender": msg.sender, "message": msg.message, "timestamp": msg.timestamp}
        for msg in undelivered_messages
    ]}

if __name__ == '__main__':
    uvicorn.run(app, host="192.168.1.168", port=3456)