FROM alpine:3.18.4
RUN curl -fsSLo pkg.tar.gz https://vendor.com/pkg.tar.gz && echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  pkg.tar.gz" | sha256sum -c
