FROM tomcat:latest

WORKDIR /usr/local/tomcat/webapps/

# back up original files
RUN mkdir ~/bak
RUN mv /usr/local/tomcat/webapps/* ~/bak/

COPY ./tj-web03.war /usr/local/tomcat/webapps/

EXPOSE 8080

CMD ["catalina.sh", "run"]
