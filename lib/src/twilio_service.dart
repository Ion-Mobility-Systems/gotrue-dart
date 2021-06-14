import 'package:gotrue/src/gotrue_response.dart';

abstract class TwilioService {
  Future<GotrueResponse> signInWithTwilio(String phoneNumber);
  Future<GotrueSessionResponse> verifySms(
      String smsCode, String authyId, String phoneNumber);
}
