FROM busybox

ENV HELLO="Hello from the Nitro enclave!"

COPY hello.sh ./

CMD ["./hello.sh"]