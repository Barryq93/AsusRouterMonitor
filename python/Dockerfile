FROM python:3.8-slim-buster

RUN pip install --upgrade pip

RUN apt-get update \
    && apt-get -y install libpq-dev gcc

WORKDIR /app

COPY requirements.txt /app/

RUN pip3 install -r requirements.txt

COPY * /app/

CMD ["python3", "-u", "./showRouterInfo.py"]