FROM python:3-slim
WORKDIR /usr/app/src
COPY udp_checksum.py .
CMD ["python", "./udp_checksum.py"]