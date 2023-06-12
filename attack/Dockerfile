FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "./arpspoof.py", "-v", "-s", "172.18.42.3", "-r", "02:42:ac:12:00:03", "-t", "172.18.42.2", "-g", "02:42:ac:12:00:02"]]