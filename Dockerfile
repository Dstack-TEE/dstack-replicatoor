# For building the DCAP validator
FROM golang:1.22 AS go-tdx-builder
WORKDIR /root/
RUN git clone https://github.com/Ruteri/dummy-tdx-dcap
WORKDIR /root/dummy-tdx-dcap
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o dcap-verifier cmd/httpserver/main.go

FROM ubuntu:22.04

# Update and install Python
RUN apt-get update && \
    apt-get install -y python3 python3-pip

RUN apt-get install -y curl wget git dumpasn1

# Install foundry
WORKDIR /root/
RUN wget https://github.com/foundry-rs/foundry/releases/download/nightly-c3069a50ba18cccfc4e7d5de9b9b388811d9cc7b/foundry_nightly_linux_amd64.tar.gz
RUN tar -xzf ./foundry_nightly_linux_amd64.tar.gz -C /usr/local/bin

# Install the TDX checker
COPY --from=go-tdx-builder /root/dummy-tdx-dcap/dcap-verifier /usr/local/bin

# Install helios
RUN curl -L 'https://github.com/a16z/helios/releases/download/0.7.0/helios_linux_amd64.tar.gz' | tar -xzC .

# Python
WORKDIR /workdir
COPY requirements.txt ./
RUN pip install -r requirements.txt
ENV PYTHONUNBUFFERED=1

COPY replicatoor.py ./
COPY run.sh ./

# ENTRYPOINT [ ]
CMD [ "bash", "run.sh" ]
# # CMD [ "python", "replicatoor.py" ]
