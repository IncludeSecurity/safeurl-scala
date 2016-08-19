import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Await
import scala.concurrent.duration._

import com.includesecurity.safeurl._

object ConfigurationExample {
  def main(args: Array[String]) {
    //
    // Modify the default configuration
    //
    SafeURL.defaultConfiguration.lists.ip.blacklist ::= "12.34.0.0/16"

    try {
      SafeURL.validate("http://12.34.43.21")
    } catch {
      case e: DisallowedURLException => println(e.toString)
    }


    //
    // Use a custom configuration for a single request
    //
    var config = new Configuration
    config.lists.protocol.whitelist ::= "ftp"

    var futureResponse = SafeURL.fetch("ftp://cdimage.debian.org/debian-cd/7.6.0/amd64/iso-cd/SHA256SUMS", config)
    println(Await.result(futureResponse, 5000 millis).asString.split('\n').head)
  }
}
