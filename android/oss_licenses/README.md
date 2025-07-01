```
./gradlew clean :app:dependencies --configuration releaseRuntimeClasspath > oss_licenses/dependencies.txt
```

```
java -jar gradle-sbom-generator-0.0.3-all.jar oss_licenses/settings.json
```
