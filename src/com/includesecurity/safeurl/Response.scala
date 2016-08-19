/* Response.scala - Library to protect agains SSRF.
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

import java.net.URLConnection
import java.nio.file.{Paths, Files}
import java.nio.charset.Charset
import sun.misc.BASE64Encoder
import java.io.{Reader, InputStreamReader}


/** Stores the data returned by the remote server. */
class Response(private val buf: Array[Byte], private val header: Map[String,List[String]]) {
  /** Return the header of the response. */
  def getHeader: Map[String,List[String]] = header

  /** Return the response as a string. */
  def asString(charset: Charset = Charset.defaultCharset): String = new String(buf, charset)
  def asString: String = asString()     // TODO this looks weird, seems to be needed to support response.asString without ()

  /** Return the response encoded using base64. */
  def asBase64: String = new sun.misc.BASE64Encoder().encode(buf)

  /** Return the response as raw byte array. */
  def asBytes: Array[Byte] = buf.clone

  /** Save the response data to a file.
    *
    * The file Will be created if it does not already exists. Existing data will be overwritten.
    *
    * @param path the path of the file to store the data in
    * @throws IOException if an I/O error occured while writing to the file
    * @throws InvalidPathException if the path string cannot be converted to a Path
    */
  def saveToFile(path: String): Unit = Files.write(Paths.get(path), buf)
}
