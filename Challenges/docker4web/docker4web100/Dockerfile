FROM tomcat:latest

WORKDIR /usr/local/tomcat/webapps/

# back up original files
RUN mkdir ~/bak
RUN mv /usr/local/tomcat/webapps/* ~/bak/
RUN mv /etc/apt/sources.list /etc/apt/sources.list.bak

COPY ./sources.list /etc/apt/
COPY ./tj-web01.war /usr/local/tomcat/webapps/
COPY ./geckodriver /usr/local/tomcat/webapps/
COPY ./myphantomjs /usr/bin/
COPY ./myphantomjs.sh /usr/bin/
COPY ./victim.js /usr/bin/

RUN chmod u+x /usr/bin/myphantomjs
RUN chmod u+x /usr/bin/myphantomjs.sh
RUN apt-get update && apt-get -y install phantomjs && apt-get -y install xvfb

EXPOSE 8080

CMD ["catalina.sh", "run"]
