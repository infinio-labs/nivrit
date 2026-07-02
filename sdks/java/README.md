# Nivrit Java SDK

```xml
<dependency>
    <groupId>com.nivrit</groupId>
    <artifactId>nivrit-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

```java
import com.nivrit.*;

HelperCrypto crypto = new HelperCrypto();
NivritSession session = new NivritSession("http://localhost:4000", patToken, crypto);
session.authenticate(password);
JsonNode secrets = session.listSecrets(projectId, environmentId);
```

The SDK expects the `nivrit-crypto-helper` binary on `PATH` or at `NIVRIT_CRYPTO_HELPER`.

## Build

```bash
cd sdks/java
mvn package
```
