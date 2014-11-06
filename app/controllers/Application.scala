package controllers

import play.api._
import play.api.mvc._
import play.api.libs.ws._
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Await
import akka.pattern.ask
import akka.util.Timeout
import scala.concurrent.duration._
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac
import java.util.UUID
import java.sql.Timestamp
import play.mvc.Results.Redirect
import java.net.URLEncoder

object Application extends Controller {

  val requestTokenURL = "https://oauth.intuit.com/oauth/v1/get_request_token";
  val accessTokenURL = "https://oauth.intuit.com/oauth/v1/get_access_token";
  val userAuthURL = "https://appcenter.intuit.com/Connect/Begin";
  val oauthCallback = "http://localhost:9000/requestToken";
  val consumerKey = "qyprd65wBgNHyLYdB7CAzT13AeDMJb";
  val consumerSecret = "UpMk1eg0zf3VHhB8q7N0Ni0VSmpTrnfvmrJRGoir";
  var verifier = "";
  var oauth_token = ""
  var oauth_token_secret = ""
  var oauth_nonce = ""
  var timestamp = ""

  def index = Action {

    
    
    
//    val signatureBaseString="GET&https%3A%2F%2Foauth.intuit.com%2Foauth%2Fv1%2Fget_access_token&oauth_consumer_key%3Dqyprd65wBgNHyLYdB7CAzT13AeDMJb%26oauth_nonce%3D17c089a0-1bcc-4140-921c-faeaed88e4e6%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1415235062%26oauth_token%3DqyprdGXa2Daevj5IaEGgt2Bz5qcYZC1lLXHYxJ1CR34kJW9h%26oauth_verifier%3Dxmyb7ri%26oauth_version%3D1.0"
//    val secret = new SecretKeySpec(("UpMk1eg0zf3VHhB8q7N0Ni0VSmpTrnfvmrJRGoir" + "&" + "4e0HuxyF2TOwoYg7kkmScGSmTuwax7UstIRhTgUJ").getBytes, "HmacSHA1")
//      val mac = Mac.getInstance("HmacSHA1")
//      mac.init(secret)
//      val signatureByte: Array[Byte] = mac.doFinal((signatureBaseString).getBytes)
//      val signature = new sun.misc.BASE64Encoder().encode(signatureByte)
//      println("COmputed Signature : " + signature);
//      println("Encoded Signature : " + URLEncoder.encode(signature));
//    
//    
//    
//    System.exit(0);
    
    val requestToken = getRequestToken
    Redirect(userAuthURL + "?oauth_token=" + requestToken);
    //Ok(views.html.index("Your new application is ready."))
  }

  def getRequestToken: String =
    {
      var oauth_nonce = UUID.randomUUID();
      var timestamp = System.currentTimeMillis() / 1000;
      val queryString = "?oauth_callback=http%3A%2F%2Flocalhost%3A9000%2FrequestToken&oauth_consumer_key=qyprd65wBgNHyLYdB7CAzT13AeDMJb&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=HMAC-SHA1&oauth_timestamp=" + timestamp + "&oauth_version=1.0";
      println("querystring = " + queryString);
      val signatureBaseString = "GET&https%3A%2F%2Foauth.intuit.com%2Foauth%2Fv1%2Fget_request_token&oauth_callback%3Dhttp%253A%252F%252Flocalhost%253A9000%252FrequestToken%26oauth_consumer_key%3Dqyprd65wBgNHyLYdB7CAzT13AeDMJb%26oauth_nonce%3D" + oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_version%3D1.0";

      println("here2");
      val secret = new SecretKeySpec((consumerSecret + "&").getBytes, "HmacSHA1")

      val mac = Mac.getInstance("HmacSHA1")
      mac.init(secret)
      val signatureByte: Array[Byte] = mac.doFinal((signatureBaseString).getBytes)
      val signature = new sun.misc.BASE64Encoder().encode(signatureByte)
      println("COmputed Signature" + signature);
      val futureResult: Future[play.api.libs.ws.Response] = WS.url(requestTokenURL + queryString + "&oauth_signature=" + signature).get;

      //    .get().map {
      //  response =>
      //    {
      //      println(response.xml);
      //      response.xml \ "message"
      //    }

      implicit val timeout = Timeout(5 seconds)
      val result = Await.result(futureResult, timeout.duration).asInstanceOf[play.api.libs.ws.Response];
      println(result.body);
      
      
       println("%%%%%%%Result.body" + result.body);
      
       //Convert result body into Map of key value pairs
       //Example Result : oauth_token_secret=O3wXrEL9wVSz4CbSkIoiVB94v6fm6kFUN6fKs5OI&oauth_callback_confirmed=true&oauth_token=qyprdqstWNGYcfUCxWm5xwttmk0wrt7jzGO8vyKI0lFGlwej
    val mapOfResultBody = result.body.split("&").map(_ split "=") collect { case Array(k, v) => (k, v) } toMap

    oauth_token_secret=mapOfResultBody("oauth_token_secret").toString()
    
    mapOfResultBody("oauth_token").toString()
//    println("----->" + mapOfResultBody.values)
//       
//    
//    
//    
//    
//      val array_split_ampersand = result.body.toString().split("&")
//      val array_split_equal = array_split_ampersand(2).split("=")
//      println("Returning = " + array_split_equal(1))
//      array_split_equal(1);

    }

  def getAccessToken =
    {
      var oauth_nonce = UUID.randomUUID();
      var timestamp = System.currentTimeMillis() / 1000;
     // val queryString = "?oauth_callback=oob&oauth_consumer_key=qyprd65wBgNHyLYdB7CAzT13AeDMJb&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=HMAC-SHA1&oauth_timestamp=" + timestamp + "&oauth_token=" + oauth_token + "&oauth_verifier=" + verifier + "&oauth_version=1.0";
    // val queryString = "?oauth_callback=oob + "&oauth_signature_method=HMAC-SHA1" + ;
// val queryString = "?oauth_verifier=" + verifier + "&oauth_token=" + oauth_token + "&oauth_nonce=" + oauth_nonce + "&oauth_consumer_key=qyprd65wBgNHyLYdB7CAzT13AeDMJb" + "&oauth_signature_method=HMAC-SHA1" + "&oauth_timestamp=" + timestamp +  "&oauth_version=1.0";
val queryString = "?oauth_consumer_key=qyprd65wBgNHyLYdB7CAzT13AeDMJb&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=HMAC-SHA1&oauth_timestamp=" + timestamp + "&oauth_token=" + oauth_token + "&oauth_verifier=" + verifier+"&oauth_version=1.0"
      //val queryString = "?oauth_verifier=" + verifier +  "&oauth_nonce=" + oauth_nonce + "&oauth_consumer_key=qyprd65wBgNHyLYdB7CAzT13AeDMJb" +  "&oauth_timestamp=" + timestamp +  "&oauth_version=1.0";
      //val queryString = "?oauth_consumer_key=qyprd65wBgNHyLYdB7CAzT13AeDMJb&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=HMAC-SHA1&oauth_timestamp=" + timestamp + "&oauth_token=" + oauth_token 	+ "&oauth_verifier=8dmhcx4&oauth_version=1.0";
      
 
      println("querystring = " + queryString);
     
      //val signatureBaseString = "GET&https%3A%2F%2Foauth.intuit.com%2Foauth%2Fv1%2Fget_access_token&oauth_consumer_key%3Dqyprd65wBgNHyLYdB7CAzT13AeDMJb%26oauth_nonce%3D18fd7250-f203-411d-8c10-8e94bbe57b39%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1415210620%26oauth_token%3DqyprdaXult6TingQ5lH8X9thKGzqVJZmrSoucdksz8TkmZrf%26oauth_verifier%3D8dmhcx4%26oauth_version%3D1.0";
    //  val signatureBaseString = "GET&https%3A%2F%2Foauth.intuit.com%2Foauth%2Fv1%2Fget_access_token&oauth_consumer_key%3Dqyprd65wBgNHyLYdB7CAzT13AeDMJb%26oauth_nonce%3D" +oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_token%3D" + oauth_token + "%26oauth_verifier%3D" + verifier + "%26oauth_version%3D1.0";
     // val signatureBaseString = "GET&https%3A%2F%2Foauth.intuit.com%2Foauth%2Fv1%2Fget_access_token&oauth_verifier%3D" + verifier + "%26oauth_token%3D" + oauth_token +"%26oauth_nonce%3D" +oauth_nonce  + "&oauth_consumer_key=qyprd65wBgNHyLYdB7CAzT13AeDMJb" + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_version%3D1.0";
val signatureBaseString = "GET&https%3A%2F%2Foauth.intuit.com%2Foauth%2Fv1%2Fget_access_token&oauth_consumer_key%3Dqyprd65wBgNHyLYdB7CAzT13AeDMJb%26oauth_nonce%3D" +oauth_nonce+"%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" +timestamp+"%26oauth_token%3D" + oauth_token + "%26oauth_verifier%3D" + verifier + "%26oauth_version%3D1.0"
      println("signatureBaseString:" + signatureBaseString);
      val secret = new SecretKeySpec(("UpMk1eg0zf3VHhB8q7N0Ni0VSmpTrnfvmrJRGoir" + "&" + oauth_token_secret).getBytes, "HmacSHA1")
      val mac = Mac.getInstance("HmacSHA1")
      mac.init(secret)
      val signatureByte: Array[Byte] = mac.doFinal((signatureBaseString).getBytes)
      val signature = new sun.misc.BASE64Encoder().encode(signatureByte)
      println("COmputed Signature : " + signature);
      println("Complete URL : " + accessTokenURL + queryString + "&oauth_signature=" + URLEncoder.encode(signature))
      val futureResult: Future[play.api.libs.ws.Response] = WS.url(accessTokenURL + queryString + "&oauth_signature=" + URLEncoder.encode(signature)).get;

      //    .get().map {
      //  response =>
      //    {
      //      println(response.xml);
      //      response.xml \ "message"
      //    }

      implicit val timeout = Timeout(5 seconds)
      val result = Await.result(futureResult, timeout.duration).asInstanceOf[play.api.libs.ws.Response];
      println("--->GetAccessTokenBody : " + result.body)
     
//      val array_split_ampersand = result.body.toString().split("&")
//      val array_split_equal = array_split_ampersand(2).split("=")
//      println("Returning = " + array_split_equal("oauth_token_secret"))
//      
//       oauth_token_secret = result.body..getQueryString("oauth_token_secret").getOrElse("")
    //mapOfResultBody.map(entry => println("------>" + entry._1 + "------" + entry._2))
   // println("-----------> oauth_token_secret" + oauth_token_secret);

    }

  def requestToken = Action { implicit request =>

    println("Inisde" + request);
    println("body	" + request.getQueryString("oauth_verifier"));
    verifier = request.getQueryString("oauth_verifier").getOrElse("")
    oauth_token = request.getQueryString("oauth_token").getOrElse("")
   
    //  loginForm.bindFromRequest.fold(
    //    formWithErrors => BadRequest(html.login(formWithErrors)),
    //    user => Redirect(routes.Projects.index).withSession("email" -> user._1)
    getAccessToken
    Ok("")

  }

}