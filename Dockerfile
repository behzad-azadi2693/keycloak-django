FROM python:3.10

ENV PYTHONDONTWRITEBYTECODE 1

ENV PYTHONUNBUFFERED 1

WORKDIR /accounts

COPY requirements.txt /accounts/

RUN pip install --upgrade pip 
RUN pip install -r requirements.txt 

COPY . /accounts/

ARG DJANGO_PORT
ENV DJANGO_PORT=${DJANGO_PORT}

EXPOSE ${DJANGO_PORT}