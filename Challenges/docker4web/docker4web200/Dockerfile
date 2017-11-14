FROM registry.docker-cn.com/library/php:7.0-apache

RUN sed -i "s|VirtualHost \*:80|VirtualHost *:8080|" /etc/apache2/sites-enabled/000-default.conf

RUN sed -i "s|VirtualHost \*:80|VirtualHost *:8080|" /etc/apache2/sites-available/000-default.conf

RUN sed -i "s|Listen 80|Listen 8080|" /etc/apache2/ports.conf

COPY src/ /var/www/html/

EXPOSE 8080

ENTRYPOINT apache2-foreground
