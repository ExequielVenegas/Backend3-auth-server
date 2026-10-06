FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY target/auth-server-0.0.1-SNAPSHOT.jar app.jar
USER 10001:10001
EXPOSE 9000
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
