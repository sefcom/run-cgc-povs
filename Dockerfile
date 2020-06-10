FROM python:3.8

WORKDIR /opt

RUN git clone https://github.com/lungetech/cgc-challenge-corpus
RUN git clone https://github.com/mechaphish/qemu-cgc

RUN cd qemu-cgc && ./cgc_configure_opt && make

ADD run.py .
ADD run_all.py .

ENTRYPOINT ./run_all.py