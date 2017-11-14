# for pwn500

FROM ubuntu

RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y apt-utils libc6-i386 socat

RUN useradd --create-home ubuntu

WORKDIR /home/ubuntu/
COPY ./bin/pwn500 ./bin/flag /home/ubuntu/

RUN chown root:root /home/ubuntu/flag
RUN chown -R root:root /home/ubuntu/
RUN chown ubuntu:ubuntu /home/ubuntu/pwn500
RUN chmod o+x /home/ubuntu/pwn500
RUN chmod 744 /home/ubuntu/flag

EXPOSE 10000

CMD ["/bin/bash"]

ENTRYPOINT su -c "nohup socat tcp-listen:10000,reuseaddr,fork exec:./pwn500" ubuntu
