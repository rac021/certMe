
########################
# Step : Compile  ######
########################

FROM maven:3.8.4-openjdk-17-slim AS compilation_stage

ADD ./. /tmp

WORKDIR /tmp

RUN apt-get update 

RUN export TERM=xterm && mvn clean install assembly:single


########################
# Step : Build  ######
########################

FROM openjdk:17-alpine

COPY --from=compilation_stage /tmp/target/*jar-with-dependencies.jar /usr/src/myapp/certMe.jar

RUN apk upgrade --update-cache --available && apk add openssl &&  rm -rf /var/cache/apk/*

WORKDIR /usr/src/myapp

ENTRYPOINT ["java", "-jar", "certMe.jar"]


#  docker build -t rac021/cert-me -f Dockerfile . ; 
#  docker push rac021/cert-me

#  sudo docker run --rm --name cert-me -p 80:80                                  \
#                   -v  $(pwd)/letsEncrypt_Cert:/usr/src/myapp/letsEncrypt_Cert/ \
#                    rac021/cert-me                                              \
#                   -domain rac021.com                                           \
#                   -out letsEncrypt_Cert                                        \
#                   -password_pkcs12 123456                                      \
#                   -port 80                                                     \
#                   -jks                                                         \
#                   -password_jks ABCDEF


## Debug Mode ( JAVA_TOOL_OPTIONS )

#  sudo docker run -e "JAVA_TOOL_OPTIONS=\"-agentlib:jdwp=transport=dt_socket,address=0.0.0.0:11555,server=y,suspend=y\"" \
#                  --rm --name cert-me                                                                                    \
#                  -p 11555:11555                                                                                         \
#                  -p 80:80                                                                                               \
#                  -v $(pwd)/letsEncrypt_Cert:/usr/src/myapp/letsEncrypt_Cert/                                            \
#                  rac021/cert-me                                                                                         \
#                  -domain rac021.com                                                                                     \
#                  -out letsEncrypt_Cert                                                                                  \
#                  -password_pkcs12 123456                                                                                \
#                  -port 80                                                                                               \
#                  -jks                                                                                                   \
#                  -password_jks ABCDEF
