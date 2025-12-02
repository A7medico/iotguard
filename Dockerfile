FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./

# Default to using main model.yaml; override with IOTGUARD_CONFIG in compose/prod.
ENV IOTGUARD_CONFIG=configs/model.yaml

EXPOSE 5001

CMD ["python", "scripts/api_dashboard.py"]





