# SafeURL for Scala

**Note: The SafeURL libraries are no longer maintained and we recommend considering other SSRF mitigation approaches alongside application-layer SSRF protection libraries. See our [2023 blog post](https://blog.includesecurity.com/2023/03/mitigating-ssrf-in-2023/) for more details.**

### Originally Ported by [@saelo](https://github.com/saelo)

## Overview
SafeURL is a library that aids developers in protecting against a class of vulnerabilities known as [Server Side Request Forgery](http://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/). It does this by validating each part of the URL against a configurable white or black list before making an HTTP request. S
afeURL is open-source and licensed under MIT.

## Installation
Clone this repository and import it into your project.

## Implementation
SafeURL replaces the Java methods in the [URLConnection](https://docs.oracle.com/javase/7/docs/api/java/net/URLConnection.html) class that are normally used to make HTTP requests in Scala.

```scala
  try {
    //User controlled input
    val url = url_
    //Execute using SafeURL
    val resp = SafeURL.fetch(url)
    val r = Await.result(resp, 500 millis)
  } catch {
    //URL wasnt safe
  }
```
## Configuration
Options such as white and black lists can be modified. For example:

```scala
//Deny requests to specific IPs
SafeURL.defaultConfiguration.lists.ip.blacklist ::= "12.34.0.0/16"
//Deny requests to specific domains
SafeURL.defaultConfiguration.lists.domain.blacklist ::= "example.com"
```
