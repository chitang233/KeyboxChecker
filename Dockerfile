FROM python:slim
LABEL authors="chitang233"

ENV WORKDIR=/app
WORKDIR $WORKDIR
ADD . $WORKDIR
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python", "main.py"]