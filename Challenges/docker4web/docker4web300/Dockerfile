FROM tomcat:7.0.67

WORKDIR /usr/local/tomcat/webapps/

# back up original files
#RUN mkdir ~/bak
RUN rm -rf /usr/local/tomcat/webapps/*

COPY ./tj-web02.war /usr/local/tomcat/webapps/

EXPOSE 8080

CMD ["catalina.sh", "run"]
