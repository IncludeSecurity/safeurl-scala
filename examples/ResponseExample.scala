import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Await
import scala.concurrent.duration._

import com.includesecurity.safeurl.{SafeURL, Response}

/** Example code to demonstrate the usage of [[safeurl.Response]] instances. */
object ResponseExample {
  def main(Args: Array[String]) {
    val futureResponse = SafeURL.fetch("http://icanhazip.com")
    val response = Await.result(futureResponse, 5000 millis)

    val header = response.getHeader
    println("Header: ")
    header.foreach { case (key, list) => println(key + ": " + list.mkString(", ")) }

    println()
    println("Body: ")

    println("As string: " + response.asString.trim)
    println("As base64: " + response.asBase64)
    println("As bytes: " + response.asBytes.map("%02x " format _).mkString)

    println()

    println("Writing response to file /tmp/response")
    response saveToFile "/tmp/response"
    println("Done")
  }
}
