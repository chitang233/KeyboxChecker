FROM python:latest
LABEL authors="chitang233"

ENV WORKDIR /app
WORKDIR $WORKDIR
ADD . $WORKDIR
RUN pip install --upgrade --no-cache-dir pip && pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python", "main.py"]