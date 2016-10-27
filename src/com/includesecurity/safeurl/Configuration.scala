/* Configuration.scala - Library to protect agains SSRF.
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


/** Access lists for the various parts of a URL. */
class AccessList {
  var whitelist: List[String] = Nil
  var blacklist: List[String] = Nil
}

/** Contains an AccessList for each part of the URL that is validated. */
class ListContainer {
  var ip: AccessList = new AccessList
  var port: AccessList = new AccessList
  var domain: AccessList = new AccessList
  var protocol: AccessList = new AccessList
}

/** SafeURL configuration.
  *
  * Stores the black- and whitelists used by SafeURL as well
  * as some other configuration properties.
  *
  * Has secure defaults.
  */
class Configuration {
  /** Do secure redirects, revalidate each redirect location first. */
  var secureRedirects: Boolean = true

  /** Support IPv6, disabled by default since the default blacklist relies on NAT for security */
  var supportIPv6: Boolean = false

  /** The maximum number of redirects SaveCurl will follow. */
  var maxRedirects: Int = 20

  /** Determines whether SafeURL will pin DNS entries, preventing DNS rebinding attacks. */
  var pinDNS: Boolean = true

  /** When a protocol is allowed also allow its default port. */
  var allowDefaultPort: Boolean = true

  /** Access lists for the various parts of a URL. */
  var lists: ListContainer = Configuration.defaultAccessLists
}

object Configuration {
  def defaultAccessLists: ListContainer = {
    val lists = new ListContainer
    lists.ip.blacklist = "0.0.0.0/8"       ::
                         "10.0.0.0/8"      ::
                         "100.64.0.0/10"   ::
                         "127.0.0.0/8"     ::
                         "169.254.0.0/16"  ::
                         "172.16.0.0/12"   ::
                         "192.0.0.0/29"    ::
                         "192.0.2.0/24"    ::
                         "192.88.99.0/24"  ::
                         "192.168.0.0/16"  ::
                         "198.18.0.0/15"   ::
                         "198.51.100.0/24" ::
                         "203.0.113.0/24"  ::
                         "224.0.0.0/4"     ::
                         "240.0.0.0/4"     ::
                         Nil

    lists.port.whitelist = "80" :: "8080" :: "443" :: Nil
    lists.protocol.whitelist = "http" :: "https" :: Nil

    lists
  }
}
