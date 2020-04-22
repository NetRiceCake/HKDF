# HKDF

HKDF is a simple key derivation function (KDF) based on a Hmac

[![Version](https://img.shields.io/badge/Version-1.1-blue.svg)](https://github.com/NetRiceCake/HKDF/)

### Using in Gradle :
```
repositories {
  mavenCentral()
}

dependencies {
  implementation 'com.github.netricecake:hkdf:1.1'
}
```

### Using in Maven :
```
<dependencies>
  <dependency>
    <groupId>com.github.netricecake</groupId>
    <artifactId>hkdf</artifactId>
    <version>1.1</version>
  </dependency>
</dependencies>
```

### How to use :

Get instace :
```
HKDF.fromHmacSha256() //Use HmacSHA256
HKDF.fromHmacSha384() //Use HmacSHA384
```

### Methods

Extract :
```
extract(byte[] salt, byte[] keyMaterial)
```

Expand :
```
expand(byte[] key, byte[] info, int outLengthBytes)
```

ExpandLabel :
```
expandLabel(byte[] key, String label, byte[] context, int length)
```