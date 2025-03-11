from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import uvicorn
import requests

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
    ip_address = Column(String, nullable=True)  # Поле для хранения IP-адреса

# Модель сообщения
class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, index=True)
    receiver = Column(String, index=True)
    message = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Создание таблиц в базе данных
Base.metadata.create_all(bind=engine)

# Инициализация FastAPI
app = FastAPI(
    title="Локальный мессенджер",
    description="API для локального мессенджера с использованием FastAPI и SQLAlchemy.",
    version="1.0.0",
    contact={
        "name": "Поддержка",
        "email": "support@example.com",
    },
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
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Эндпоинт для установки IP-адреса
@app.post(
    "/set_ip/",
    summary="Установка IP-адреса",
    description="Установка IP-адреса клиента для получения сообщений.",
)
async def set_ip(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    client_host = request.client.host  # Получаем IP-адрес клиента
    current_user.ip_address = client_host
    db.commit()
    return {"status": "IP-адрес обновлен", "ip_address": client_host}

# Эндпоинт для отправки сообщения через сервер
@app.post(
    "/send_message/",
    summary="Отправка сообщения через сервер",
    description="Отправка сообщения другому пользователю через сервер.",
)
async def send_message(receiver_username: str, message: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Находим получателя в базе данных
    receiver = db.query(User).filter(User.username == receiver_username).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Получатель не найден")
    if not receiver.ip_address:
        raise HTTPException(status_code=404, detail="IP-адрес получателя не установлен")

    # Сохраняем сообщение в базе данных
    new_message = Message(sender=current_user.username, receiver=receiver.username, message=message)
    db.add(new_message)
    db.commit()

    # Пересылаем сообщение на IP-адрес получателя
    try:
        response = requests.post(
            f"http://{receiver.ip_address}:3456/receive_message/",
            json={"sender": current_user.username, "message": message}
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Не удалось отправить сообщение: {str(e)}")

    return {"status": "Сообщение отправлено", "receiver": receiver.username, "ip_address": receiver.ip_address}

# Эндпоинт для получения сообщений (для клиента)
@app.post(
    "/receive_message/",
    summary="Получение сообщения",
    description="Эндпоинт для получения сообщений от других пользователей.",
)
async def receive_message(sender: str, message: str):
    # Здесь клиент может обработать входящее сообщение
    return {"status": "Сообщение получено", "sender": sender, "message": message}

if __name__ == '__main__':
    uvicorn.run(app, host="192.168.1.168", port=3456)