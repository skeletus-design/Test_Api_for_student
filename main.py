from fastapi import FastAPI
import uvicorn

app = FastAPI()

class Main:
    def __init__(self):
        self.Input = None

    def get_prompt(self):
        self.Input = input("Введите значение: ")

# Создаем экземпляр класса Main
main_app = Main()

# Маршрут FastAPI
@app.get("/")
async def read_root():
    if main_app.Input is None:
        return {"message": "Значение не введено"}
    return {"main": main_app.Input}

if __name__ == '__main__':
    # Ввод значения перед запуском сервера
    main_app.get_prompt()
    
    # Запуск сервера
    uvicorn.run(app, host="192.168.1.168", port=3456)