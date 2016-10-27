/* SafeURL.scala - Library to protect agains SSRF.
 * Pull requests are welcome, please find this tool hosted on http://github.com/IncludeSecurity
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2014 Include Security <info [at sign] includesecurity.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.includesecurity.safeurl

import java.net._
import java.util.regex.Pattern
import java.io.ByteArrayOutputStream
import scala.collection.JavaConverters._
import scala.concurrent._
import scala.concurrent.ExecutionContext.Implicits.global
import javax.net.ssl._
import java.security.cert.X509Certificate


/** Enumeration of the different parts of a URL processed by SafeURL. */
object URLPart extends Enumeration {
  val Protocol, Host, IP, Port = Value
}

// TODO maybe give this a better name?
/** Enumeration of the possible reasons a URL part was forbidden. */
object Reason extends Enumeration {
  val Blacklisted, NotWhitelisted = Value
}

/** Custom exception class thrown by SafeURL if a URL is disallowed. */
case class DisallowedURLException(part: URLPart.Value, value: String, reason: Reason.Value) extends Exception {
  override def getMessage(): String = reason match {
    case Reason.NotWhitelisted => part + " \"" + value + "\" is not whitelisted."
    case Reason.Blacklisted => part + " \"" + value + "\" is blacklisted."
  }
}

object SafeURL {
  /** Default configuration for SafeURL. Can be modified to change SafeURLs behaviour application wide. */
  var defaultConfiguration = new Configuration

  // See http://stackoverflow.com/questions/7648872/can-i-override-the-host-header-where-using-javas-httpurlconnection-class
  // This has to be called before the HTTPUrlConnection class is loaded since the value will only
  // be read once when the class is being initialized. See sun/net/www/protocol/http/HttpURLConnection.java
  // Note: To make sure things work we could do some hacky things here like reloading the class
  // or using reflection to change the private allowRestrictedHeaders member of the HTTPUrlConnection class.
  // I think it's cleaner not to do so though.
  System.setProperty("sun.net.http.allowRestrictedHeaders", "true")


  /** Test if the provided address is an IP address.
    *
    * Note: Does not check whether the IP is valid.
    *
    * @param addr the string to check
    * @return true if addr is an IP address
    */
  private def isIP(addr: String): Boolean = {
    // Why don't we check if the IP address is valid as well? See http://vernon.mauery.com/content/projects/linux/ipv6_regex
    // It's easier to ask the network libraries to resolve the IP later on.
    (addr matches "(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})") ||
    (addr matches "\\[[0-9A-Fa-f:]*\\]")
  }

  /** Resolve the given hostname to it's IP addresses.
    *
    * If an IP address is passed this function will return an array
    * containing just that IP.
    * IPv6 addresses may be surrounded with [ ] (URL notation).
    *
    * @param host hostname or IP address to resolve
    * @return an array of IP addresses the hostname/IP resolves to
    */
  private def resolve(host: String, cfg: Configuration = defaultConfiguration): Array[String] = {
    var hosts = InetAddress.getAllByName(host)
    if (!cfg.supportIPv6) {
      val v4Hosts = hosts filter (_.isInstanceOf[Inet4Address])
      if (v4Hosts.isEmpty && !hosts.isEmpty) {
        // Treat IPv6-only results as if there was a lookup error,
        // doesn't seem to be a way to force an IPv4-only lookup.
        throw new UnknownHostException(host + ": Name or service not known");
      }
      hosts = v4Hosts
    }
    hosts map (_.getHostAddress)
  }

  /** Check if the given IP address lies within the subnet given in CIDR notation.
    *
    * Supports IPv4 and IPv6.
    *
    * @param ipString the IP as string
    * @param cidrString the subnet in CIDR notation
    * @return true if the IP lies within the subnet, false otherwise
    */
  private def cidrMatch(ipString: String, cidrString: String): Boolean = {
    val parts = cidrString split '/'

    val ip = InetAddress.getByName(ipString).getAddress
    val subnet = InetAddress.getByName(parts(0)).getAddress

    if (ip.length != subnet.length) {
      // can't compare IPv6 with IPv4 address
      return false
    }

    if (parts.length < 2) {
      // can only do this now since there are multiple string representations of the same IP address
      return ip.deep == subnet.deep
    } else {
      var bits = 0
      try {
        bits = parts(1).toInt
      } catch {
        case e: NumberFormatException => throw new IllegalArgumentException("Invalid CIDR notation: " + cidrString)
      }
      if (bits < 0 || bits > ip.length * 8) {
        throw new IllegalArgumentException("Invalid CIDR notation: " + cidrString)
      }
      if (bits == 0) {
        return false
      }

      for (i <- 0 until bits/8) {
        if (ip(i) != subnet(i)) {
          return false
        }
      }
      if (bits % 8 != 0) {
        // compare remaining bits
        val nextByte = bits/8
        if (ip(nextByte) >> (8-bits%8) != (subnet(nextByte) >> (8-bits%8))) {
          return false
        }
      }
    }

    true
  }

  /** Check if the given hostname belongs to a domain.
    *
    * @param hostname the hostname
    * @param domain the domain
    * @return true if the host is part of the domain
    */
  private def domainMatch(hostname: String, domain: String): Boolean = {
    // Check if last part of the hostname matches the domain name
    (hostname.toLowerCase) matches ("^.*" + Pattern.quote(domain.toLowerCase) + "$")
  }

  /** Check if the provided hostname matches the given common name.
    *
    * @param hostname the hostname to check
    * @param cn the common name
    * @return true if the hostname matches the common name
    */
  private def cnMatch(hostname: String, cn: String): Boolean = {
    if (cn startsWith "*")
      // *.domain.com is valid for
      //   secure.domain.com
      //   www.domain.com
      // but not for
      //   www.secure.domain.com    (only one level)
      //   domain.com
      (hostname.toLowerCase) matches ("^[0-9a-z-]+" + Pattern.quote(cn.substring(1).toLowerCase) + "$")
    else
      cn.toLowerCase == hostname.toLowerCase
  }

  /** Validate the given part of a URL.
    *
    * Validation is performed by comparing the given value to the values
    * in the black- and whitelist.
    * Comparison is performed by calling the provided function with the value
    * as first argument and the list entry as second argument. All arguments
    * are converted to lower case before passing them to the provided function.
    *
    * @param part the part of the URL that should be verified
    * @param value the value to verify
    * @param al the access list to validate against
    * @param matches a function to check if the value matches an element from one of the lists
    **/
  private def validate(part: URLPart.Value, value: String, al: AccessList, matches: (String, String) => Boolean): Unit = {
    val whitelist = al.whitelist map (_.toLowerCase)
    val blacklist = al.blacklist map (_.toLowerCase)
    val matchesValue = matches(value.toLowerCase, _: String)

    if (!(whitelist isEmpty)) {
      if (!(whitelist exists matchesValue)) {
        throw new DisallowedURLException(part, value, Reason.NotWhitelisted)
      }
    }

    if (blacklist exists matchesValue) {
      throw new DisallowedURLException(part, value, Reason.Blacklisted)
    }
  }

  /** Validate the provided URL.
    *
    * This implements the main SSRF protection by matching
    * the provided URL against a set of black- and whitelists
    * specified in the [[SafeURL.Configuration]] object.
    * If the URL is disallowed an exception is thrown.
    * Also takes care of DNS pinning by replacing the hostname with an IP
    * address and returning the new URL.
    *
    * WARNING: If you are using this function in combination with some external
    * library to do the actual work make sure it does not automatically follow redirects.
    * Also you will not be protected against DNS rebinding without further actions.
    *
    * @param urlString the URL to validate
    * @param cfg the configuration to use
    *
    * @throws MalformedURLException if the URL is malformed
    * @throws DisallowedURLException if the URL is not allowed
    * @throws UnknownHostException if the hostname could not be resolved
    * @throws NullPointerException if the configuration is null
    *
    * @return a tuple consisting of the (possibly modified) new URL and the target hostname (needed when doing DNS pinning)
    */
  def validate(urlString: String, cfg: Configuration = defaultConfiguration): (String, String) = {
    var newUrlString = urlString
    val url = new URL(urlString)
    // Define a custom equals function for strings, used for validate() below.
    // Note: toLowerCase() is performed twice (validate() does it too).
    // This might not be a bad idea to prevent future code changes from introducing security bugs.
    val equals = ((a: String, b: String) => a.toLowerCase == b.toLowerCase)

    // Validate the protocol
    val proto = url.getProtocol.toLowerCase
    validate(URLPart.Protocol, proto, cfg.lists.protocol, equals)

    // Validate the port
    var port = url.getPort
    if (port == -1) {
      port = url.getDefaultPort
    }
    if (!cfg.allowDefaultPort || port != url.getDefaultPort) {
      validate(URLPart.Port, port.toString, cfg.lists.port, equals)
    }

    // Validate the hostname
    val host = url.getHost  // If the host was specified as an IPv6 address it will be enclosed in [ ]
    if (!isIP(host)) {
      validate(URLPart.Host, host, cfg.lists.domain, domainMatch)
    }

    // Validate the IP
    val ips = resolve(host, cfg)
    for (ip <- ips) {
      // Note: Doing it this way means that when IP whitelisting is active,
      // every IP a given hostname resolves to must be in the whitelist.
      validate(URLPart.IP, ip, cfg.lists.ip, cidrMatch)
    }

    // perform DNS pinning if needed
    if (cfg.pinDNS && !isIP(host)) {
      var ip = ips(0)
      if (ip contains ":") {
        // IPv6 needs special treatment
        ip = "[" + ip + "]"
      }

      // We can't just replace the first occurance of the hostname since
      // someone might supply a URL like this: http://evildomain.com:pass@evildomain.com
      // This could then be used to bypass DNS pinning and access internal IPs.
      // Replacing every occurance is also not possible as that could destroy valid URLs.
      newUrlString = proto + "://"
      if (url.getUserInfo != null) {
          newUrlString += url.getUserInfo + "@"
      }
      newUrlString += ip + ":" + port + url.getFile
      if (url.getRef != null) {
          newUrlString += "#" + url.getRef
      }
    }

    (newUrlString, host.replace("[", "").replace("]", ""))
  }

  /** Check if the provided URL is allowed.
    *
    * Same as validate() but does not throw an exception, just returns true or false.
    * See the warning for validate().
    *
    * @param urlString the URL to check
    * @param cfg the configuration to use
    *
    * @throws MalformedURLException if the URL is malformed
    * @throws NullPointerException if the configuration is null
    *
    * @return true if the URL is allowed, false otherwise
    */
  def allowed(urlString: String, cfg: Configuration = defaultConfiguration): Boolean = {
    try {
      validate(urlString, cfg)
    } catch {
      case e: DisallowedURLException => return false
    }

    true
  }

  /** Fetch the resource identified by the given URL.
    *
    * This offloads most of the SSRF protection to validate(). It does
    * however implement safe redirect following and in part DNS pinning.
    *
    * The returned Future may contain all exceptions thrown by validate as well
    * as a ProtocolException if the server redirected too many times and
    * an IOException if there was an error while communicating with the remote server.
    *
    * @param url the URL of the resource to fetch
    * @param config the configuration to use
    *
    * @return a Future that will contain the response or an exception at some point
    */
  def fetch(url: String, cfg: Configuration = defaultConfiguration): Future[Response] = {
    Future {
      var conn: URLConnection = null
      var isRedirect: Boolean = false
      var redirectCount = 0
      var currUrl = url

      do {
        isRedirect = false
        var tuple = validate(currUrl, cfg)
        var newUrl = tuple._1
        var hostname = tuple._2

        conn = new URL(newUrl).openConnection()
        if (cfg.pinDNS) {
          conn.setRequestProperty("Host", hostname)
        }

        if (cfg.secureRedirects && conn.isInstanceOf[HttpURLConnection]) {
          if (cfg.pinDNS && conn.isInstanceOf[HttpsURLConnection]) {
            // Since we've replaced the hostname with the IP address
            // we now need to get java.net to accept the certificate.
            // From the documentation:
            // "During handshaking, if the URL's hostname and the server's identification
            // hostname mismatch, the verification mechanism can call back to implementers
            // of this interface to determine if this connection should be allowed."
            var httpsConn = conn.asInstanceOf[HttpsURLConnection]
            httpsConn.setHostnameVerifier(new HostnameVerifier {
              def verify(urlHostname: String, session: SSLSession): Boolean = {
                var cert = session.getPeerCertificates()(0)
                if (cert.isInstanceOf[X509Certificate]) {
                  val x509 = cert.asInstanceOf[X509Certificate]
                  val subject = x509.getSubjectX500Principal.getName
                  val commonNames = subject split "," filter (_ startsWith "CN=") map (_ substring 3)
                  val found = commonNames exists (cnMatch(hostname, _))

                  found
                } else {
                  // can only deal with X509 certificates
                  false
                }
              }
            })
          }

          var httpConn = conn.asInstanceOf[HttpURLConnection]
          httpConn.setInstanceFollowRedirects(false)

          var respCode = httpConn.getResponseCode
          if (respCode >= 300 && respCode < 400) {
            // it's a redirect
            if (redirectCount >= cfg.maxRedirects) {
              throw new ProtocolException("Server redirected too many times (" + redirectCount + ")")
            }

            currUrl = httpConn.getHeaderField("Location")
            redirectCount += 1
            isRedirect = true
          }
        }
      } while (isRedirect)

      val is = conn.getInputStream
      val os = new ByteArrayOutputStream(is.available)
      val buf = new Array[Byte](1024)
      var len = 0

      while ({ len = is.read(buf); len != -1 }) {
        os.write(buf, 0, len)
      }

      is.close()

      new Response(os.toByteArray, conn.getHeaderFields.asScala map { case (k, v) => k -> v.asScala.toList } toMap)
    }
  }
}
