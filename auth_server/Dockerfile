FROM busybox
EXPOSE 5001
ENTRYPOINT ["/auth_server"]
CMD ["/config/auth_config.yml"]
COPY ./Files/ssl/d2hub.com.cert /ssl/d2hub.com.cert
COPY ./Files/ssl/d2hub.com.key /ssl/d2hub.com.key
COPY ./Files/config/auth_config.yml /config/auth_config.yml
COPY auth_server .
