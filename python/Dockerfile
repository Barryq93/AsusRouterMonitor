FROM python:3.8-slim-buster

RUN pip install --upgrade pip

# Install dependencies for mysql-connector-python
RUN apt-get update && apt-get install -y \
    libmariadb-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip3 install -r requirements.txt

COPY *.py /app/

CMD ["python3", "-u", "./ShowRouterInfo.py"]