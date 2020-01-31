FROM maven AS build-env
ADD . /apostille
WORKDIR /apostille
RUN mvn package

FROM gcr.io/distroless/java:11
COPY --from=build-env /apostille/target /apostille
WORKDIR /apostille
CMD ["apostille-1.1.jar"]
ENTRYPOINT ["java","-jar","apostille-1.1.jar"]
