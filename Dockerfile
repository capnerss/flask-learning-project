# 1. Используем легкий образ Python
FROM python:3.10-slim

# 2. Отключаем создание кеш-файлов .pyc (они не нужны в контейнере)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 3. Создаем рабочую папку
WORKDIR /app

# 4. Сначала копируем только файл зависимостей (для кэширования Docker)
COPY requirements.txt .

# 5. Устанавливаем библиотеки
RUN pip install --no-cache-dir -r requirements.txt

# 6. Теперь копируем весь остальной код проекта
COPY . .

# 7. Указываем команду запуска: Gunicorn на порту 10000 (стандарт Render)
# app:app означает "файл app.py : объект app внутри него"
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:10000", "app:app"]