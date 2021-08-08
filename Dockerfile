FROM python:3.7-slim-buster

# configure poetry
RUN pip install poetry
RUN poetry config virtualenvs.create false

# install dependencies
WORKDIR /app
COPY . /app
RUN poetry install --no-dev

# delete caches
RUN rm -rf ~/.cache/pip

# you can rewrite this command when running the docker container.
# ex. docker run -t --rm -v $(pwd):/app reg2es:latest reg2json NTUSER.DAT out.json
CMD ["reg2es", "-h"]
