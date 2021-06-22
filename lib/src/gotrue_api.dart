import 'package:gotrue/gotrue.dart';
import 'package:gotrue/src/twilio_service.dart';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:jose/jose.dart';
import 'cookie_options.dart';
import 'fetch.dart';
import 'fetch_options.dart';
import 'gotrue_error.dart';
import 'gotrue_response.dart';
import 'provider.dart';
import 'session.dart';
import 'user.dart';
import 'user_attributes.dart';

class GoTrueApi with TwilioService {
  String url;
  Map<String, String> headers;
  CookieOptions? cookieOptions;
  late String _accountSid, _serviceSid, _authToken;
  String _twilioAuthyBaseUrl = 'https://api.authy.com/protected/json';

  GoTrueApi(this.url, {Map<String, String>? headers, this.cookieOptions})
      : headers = headers ?? {};

  // void setTwilioAuthyApiKey(String key) => _twilioAuthyApiKey = key;
  void setUpTwilioAuthyApi(
      String accountSid, String serviceSid, String authToken) {
    _accountSid = accountSid;
    _serviceSid = serviceSid;
    _authToken = authToken;
  }

  /// Creates a new user using their email address.
  Future<GotrueSessionResponse> signUpWithEmail(
      String email, String password) async {
    try {
      final body = {'email': email, 'password': password};
      final options = FetchOptions(headers);
      final response = await fetch.post('$url/signup', body, options: options);
      if (response.error != null) {
        return GotrueSessionResponse(error: response.error);
      } else if ((response.rawData as Map<String, dynamic>)['access_token'] ==
          null) {
        // email validation required
        return GotrueSessionResponse();
      } else {
        final session =
            Session.fromJson(response.rawData as Map<String, dynamic>);
        return GotrueSessionResponse(data: session);
      }
    } catch (e) {
      return GotrueSessionResponse(error: GotrueError(e.toString()));
    }
  }

  /// Logs in an existing user using their email address.
  Future<GotrueSessionResponse> signInWithEmail(
      String email, String password) async {
    try {
      final body = {'email': email, 'password': password};
      final options = FetchOptions(headers);
      final response = await fetch.post('$url/token?grant_type=password', body,
          options: options);
      if (response.error != null) {
        return GotrueSessionResponse(error: response.error);
      } else {
        final session =
            Session.fromJson(response.rawData as Map<String, dynamic>);
        return GotrueSessionResponse(data: session);
      }
    } catch (e) {
      return GotrueSessionResponse(error: GotrueError(e.toString()));
    }
  }

  /// Sends a magic login link to an email address.
  Future<GotrueJsonResponse> sendMagicLinkEmail(String email) async {
    try {
      final body = {'email': email};
      final options = FetchOptions(headers);
      final response =
          await fetch.post('$url/magiclink', body, options: options);
      if (response.error != null) {
        return GotrueJsonResponse(error: response.error);
      } else {
        return GotrueJsonResponse(
            data: response.rawData as Map<String, dynamic>?);
      }
    } catch (e) {
      return GotrueJsonResponse(error: GotrueError(e.toString()));
    }
  }

  /// Sends an invite link to an email address.
  Future<GotrueJsonResponse> inviteUserByEmail(String email) async {
    try {
      final body = {'email': email};
      final options = FetchOptions(headers);
      final response = await fetch.post('$url/invite', body, options: options);
      if (response.error != null) {
        return GotrueJsonResponse(error: response.error);
      } else {
        return GotrueJsonResponse(
            data: response.rawData as Map<String, dynamic>?);
      }
    } catch (e) {
      return GotrueJsonResponse(error: GotrueError(e.toString()));
    }
  }

  /// Sends a reset request to an email address.
  Future<GotrueJsonResponse> resetPasswordForEmail(String email) async {
    try {
      final body = {'email': email};
      final options = FetchOptions(headers);
      final response = await fetch.post('$url/recover', body, options: options);
      if (response.error != null) {
        return GotrueJsonResponse(error: response.error);
      } else {
        return GotrueJsonResponse(
            data: response.rawData as Map<String, dynamic>?);
      }
    } catch (e) {
      return GotrueJsonResponse(error: GotrueError(e.toString()));
    }
  }

  /// Removes a logged-in session.
  Future<GotrueResponse> signOut(String jwt) async {
    try {
      final headers = {...this.headers};
      headers['Authorization'] = 'Bearer $jwt';
      final options = FetchOptions(headers, noResolveJson: true);
      final response = await fetch.post('$url/logout', {}, options: options);
      return response;
    } catch (e) {
      return GotrueResponse(error: GotrueError(e.toString()));
    }
  }

  String getUrlForProvider(Provider provider, ProviderOptions? options) {
    final urlParams = ['provider=${provider.name()}'];
    if (options?.scopes != null) {
      urlParams.add('scopes=${options!.scopes!}');
    }
    if (options?.redirectTo != null) {
      final encodedRedirectTo = Uri.encodeComponent(options!.redirectTo!);
      urlParams.add('redirect_to=$encodedRedirectTo');
    }
    return '$url/authorize?${urlParams.join('&')}';
  }

  /// Gets the user details.
  Future<GotrueUserResponse> getUser(String jwt) async {
    try {
      final headers = {...this.headers};
      headers['Authorization'] = 'Bearer $jwt';
      final options = FetchOptions(headers);
      final response = await fetch.get('$url/user', options: options);
      if (response.error != null) {
        return GotrueUserResponse(error: response.error);
      } else {
        final user = User.fromJson(response.rawData as Map<String, dynamic>);
        return GotrueUserResponse(user: user);
      }
    } catch (e) {
      return GotrueUserResponse(error: GotrueError(e.toString()));
    }
  }

  /// Updates the user data.
  Future<GotrueUserResponse> updateUser(
      String jwt, UserAttributes attributes) async {
    try {
      final body = attributes.toJson();
      final headers = {...this.headers};
      headers['Authorization'] = 'Bearer $jwt';
      final options = FetchOptions(headers);
      final response = await fetch.put('$url/user', body, options: options);
      if (response.error != null) {
        return GotrueUserResponse(error: response.error);
      } else {
        final user = User.fromJson(response.rawData as Map<String, dynamic>);
        return GotrueUserResponse(user: user);
      }
    } catch (e) {
      return GotrueUserResponse(error: GotrueError(e.toString()));
    }
  }

  /// Generates a new JWT.
  Future<GotrueSessionResponse> refreshAccessToken(String refreshToken) async {
    try {
      final body = {'refresh_token': refreshToken};
      final options = FetchOptions(headers);
      final response = await fetch
          .post('$url/token?grant_type=refresh_token', body, options: options);
      if (response.error != null) {
        return GotrueSessionResponse(error: response.error);
      } else {
        final session =
            Session.fromJson(response.rawData as Map<String, dynamic>);
        return GotrueSessionResponse(data: session);
      }
    } catch (e) {
      return GotrueSessionResponse(error: GotrueError(e.toString()));
    }
  }

  // TODO: not implemented yet
  void setAuthCookie() {}

  // TODO: not implemented yet
  void getUserByCookie() {}

  @override
  Future<GotrueResponse> signInWithTwilio(String phoneNumber) async {
    final String baseUrl = 'https://verify.twilio.com/v2/Services/$_serviceSid';
    final authn =
        'Basic ${base64Encode(utf8.encode('$_accountSid:$_authToken'))}';
    final String url = '$baseUrl/Verifications';
    final response = await http.post(
      Uri.parse(url),
      body: {
        'To': phoneNumber,
        'Channel': 'sms',
      },
      headers: {
        'Authorization': authn,
      },
    );
    if (response.statusCode == 200 || response.statusCode == 201) {
      return GotrueResponse(
        rawData: response.body,
      );
    } else {
      return GotrueResponse(
        error: GotrueError(
          jsonDecode(response.body)['message'].toString(),
        ),
      );
    }
    // final String newUserUrl = '$_twilioAuthyBaseUrl/users/new';
    // final String countryCode = phoneNumber
    //     .substring(0, phoneNumber.length - 10)
    //     .replaceAll(RegExp('[^0-9]'), '');
    // final String cellphone = phoneNumber.replaceAll(countryCode, '');
    // final Map<String, dynamic> dataToPass = {
    //   'cellphone': cellphone,
    //   'country_code': countryCode,
    // };
    // final FetchOptions options = FetchOptions({
    //   'X-Authy-API-Key': _twilioAuthyApiKey,
    //   'Content-Type': 'application/x-www-form-urlencoded',
    // });
    // final GotrueResponse newUserResponse = await fetch.post(
    //   newUserUrl,
    //   dataToPass,
    //   options: options,
    // );
    // if (newUserResponse.error == null) {
    //   final String userAuthyId =
    //       newUserResponse.rawData['user']['id'].toString();
    //   final String sendSmsUrl = '$_twilioAuthyBaseUrl/sms/$userAuthyId';
    //   final GotrueResponse sendSmsResponse = await fetch.get(
    //     sendSmsUrl,
    //     options: options,
    //   );
    //   if (sendSmsResponse.error == null) {
    //     Map<String, dynamic> responseData =
    //         sendSmsResponse.rawData as Map<String, dynamic>;
    //     responseData['authy_id'] = userAuthyId;
    //     sendSmsResponse.rawData = responseData;
    //     return sendSmsResponse;
    //   } else {
    //     return sendSmsResponse;
    //   }
    // } else {
    //   return newUserResponse;
    // }
  }

  @override
  Future<GotrueSessionResponse> verifySms(
      String smsCode, String phoneNumber) async {
    final String baseUrl = 'https://verify.twilio.com/v2/Services/$_serviceSid';
    final authn =
        'Basic ${base64Encode(utf8.encode('$_accountSid:$_authToken'))}';
    final String url = '$baseUrl/VerificationCheck';
    final FetchOptions options = FetchOptions({
      'Authorization': authn,
    });
    final response = await http.post(
      Uri.parse(url),
      body: {
        'To': phoneNumber,
        'Code': smsCode,
      },
      headers: {
        'Authorization': authn,
      },
    );
    final js = jsonDecode(response.body);
    if (js['status'] == 'approved') {
      final GoTrueClient client = GoTrueClient();
      final claims = JsonWebTokenClaims.fromJson({
        "exp": const Duration(hours: 4).inSeconds,
        "phone_number": phoneNumber,
      });
      final builder = JsonWebSignatureBuilder();
      builder.jsonContent = claims.toJson();
      builder.addRecipient(
        JsonWebKey.fromJson({
          "kty": "oct",
          "k":
              "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        }),
        algorithm: "HS256",
      );
      final jws = builder.build();
      final accessToken = jws.toCompactSerialization();
      final expiresIn = const Duration(hours: 4).inSeconds;
      const refreshToken = 'my_refresh_token';
      const tokenType = 'my_token_type';
      final url =
          'http://my-callback-url.com/welcome?access_token=$accessToken&expires_in=$expiresIn&refresh_token=$refreshToken&token_type=$tokenType';
      final GotrueSessionResponse response =
          await client.getSessionFromUrl(Uri.parse(url));
      return response;
    } else {
      return GotrueSessionResponse(
        error: GotrueError(
          js['message'].toString(),
        ),
      );
    }
  }

  // @override
  // Future<GotrueSessionResponse> verifySms(
  //     String smsCode, String authyId, String phoneNumber) async {
  //   final String smsVerificationUrl =
  //       '$_twilioAuthyBaseUrl/verify/$smsCode/$authyId';
  //   final FetchOptions options = FetchOptions({
  //     'X-Authy-API-Key': _twilioAuthyApiKey,
  //   });
  //   final GotrueResponse response = await fetch.get(
  //     smsVerificationUrl,
  //     options: options,
  //   );
  //   if (response.error == null) {
  //     final String email = '$phoneNumber@ionmobility.asia';
  //     final String password = '$phoneNumber/${DateTime.now()}';
  //     return signUpWithEmail(email, password);
  //   } else {
  //     return GotrueSessionResponse(error: response.error);
  //   }
  // }
}
