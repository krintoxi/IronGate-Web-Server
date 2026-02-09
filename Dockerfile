FROM python:3.11-slim

# Install PHP-CGI so your server can handle PHP files
RUN apt-get update && apt-get install -y php-cgi && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Create directories
RUN mkdir -p evidence WWW

EXPOSE 80
EXPOSE 8080
ENV TERM=xterm-256color
ENV PYTHONUNBUFFERED=1

CMD ["python", "server.py"]