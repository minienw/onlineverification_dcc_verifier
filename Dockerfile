FROM golang

WORKDIR /app
COPY . ./
RUN go get ./
COPY ./ /app
#COPY ./public_keys.json /var/opt/verifierconfig/public_keys.json
CMD ["go", "run", "./", "verification-server", "--listen-address", "0.0.0.0", "--public-keys-path", "/var/opt/verifierconfig/public_keys.json"]

EXPOSE 4003