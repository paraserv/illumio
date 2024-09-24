FROM python:3.12-slim

WORKDIR /app

COPY app/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./

ENV BASE_FOLDER=/app
ENV DOWNLOADED_FILES_FOLDER=illumio
ENV LOG_FOLDER=logs

RUN mkdir -p $DOWNLOADED_FILES_FOLDER $LOG_FOLDER

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]