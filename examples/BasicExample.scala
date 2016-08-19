import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Await
import scala.concurrent.duration._

import com.includesecurity.safeurl._

object BasicExample {
  def main(Args: Array[String]) {
    //
    // Asyncronous example
    // 
    var futureResponse = SafeURL.fetch("http://icanhazip.com")
    futureResponse onSuccess {
      case response => println(response.asString.trim)
    }

    //
    // Syncronous example
    //
    futureResponse = SafeURL.fetch("http://icanhazip.com")
    val response = Await.result(futureResponse, 5000 millis)
    println(response.asString.trim)


    //
    // Dealing with errors
    //
    futureResponse = SafeURL.fetch("file:///etc/passwd")
    futureResponse onSuccess {
      case response => println(response.asString)
    }
    futureResponse onFailure {
      case error => println(error.toString)
    }

    futureResponse = SafeURL.fetch("http://192.168.1.1/secret")
    try {
      val response = Await.result(futureResponse, 5000 millis)
    } catch {
      case DisallowedURLException(URLPart.IP, ip, _) => println("Sorry, you can't access that IP (" + ip + ")")
      case e: DisallowedURLException => println("Access denied")
    }

    // wait for asyncronous tasks to finish
    Thread.sleep(1000)
  }
}
