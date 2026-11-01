"""Small protobuf codec for Tinder's observed authentication gateway.

Field mappings verified against Tinder's public client schema on 2026-11-01:
https://tinder.com/static/build/l/chunks/async-protobuf-schema-authgateway-8036d41ebaac5496c7d2.js

This independently implemented wire codec accepts camelCase field names. Google
scalar wrappers are plain Python scalars at its boundary. It never logs payloads.
"""


class CodecError(ValueError):
    """Invalid protobuf data or an unsupported request field."""


# Entries are field number -> (field name, type), with [] for repeated messages.
# w: denotes a google.protobuf scalar wrapper rather than a bare scalar.
SCHEMAS = {
    "Phone": {1: ("phone", "string"), 2: ("refreshToken", "w:string"),
              3: ("captchaToken", "w:string"), 4: ("iosDeviceToken", "w:string"),
              5: ("androidJws", "w:string"), 6: ("androidJwsVersion", "w:int32")},
    "PhoneOtp": {1: ("phone", "w:string"), 2: ("otp", "string"), 3: ("refreshToken", "w:string")},
    "Email": {1: ("email", "string"), 2: ("refreshToken", "w:string"), 3: ("marketingOptIn", "w:bool")},
    "EmailOtp": {1: ("email", "w:string"), 2: ("otp", "string"), 3: ("refreshToken", "w:string")},
    "RefreshAuth": {1: ("refreshToken", "string")},
    "PhoneOtpResend": {1: ("phone", "w:string"), 2: ("refreshToken", "w:string"),
                       3: ("iosDeviceToken", "w:string"), 4: ("androidJws", "w:string"),
                       5: ("androidJwsVersion", "w:int32")},
    "EmailOtpResend": {1: ("email", "w:string"), 2: ("refreshToken", "w:string")},
    "GetInitialState": {1: ("refreshToken", "w:string")},
    "PreEmail": {},
    "DismissSocialConnectionList": {1: ("refreshToken", "string")},
    "ExistingPhoneOTP": {1: ("otp", "string"), 2: ("refreshToken", "w:string")},
    "ExistingPhoneOTPResend": {1: ("refreshToken", "w:string"), 2: ("type", "w:string")},
    "Captcha": {1: ("referenceToken", "string"), 2: ("captchaToken", "string")},
    "Timestamp": {1: ("seconds", "int64"), 2: ("nanos", "int32")},
    "MetaProto": {1: ("upstreamTime", "Timestamp"), 2: ("startTime", "Timestamp")},
    "ErrorProto": {1: ("code", "int32"), 2: ("message", "string"), 3: ("banReason", "BanReason")},
    "BanReason": {1: ("underageBan", "UnderageBan"), 2: ("banAppeal", "BanAppeal"),
                  3: ("selfieChallengeBan", "SelfieChallengeBan"), 4: ("idvChallengeBan", "IdvChallengeBan")},
    "UnderageBan": {1: ("underageTtlDurationMs", "w:int64"), 2: ("underageToken", "w:string"),
                    3: ("verification", "Verification"), 4: ("isOnboarding", "w:bool")},
    "Verification": {1: ("type", "string"), 2: ("state", "string")},
    "BanAppeal": {1: ("challengeType", "string"), 2: ("challengeToken", "string"),
                  3: ("refreshToken", "string"), 4: ("policy", "string"),
                  5: ("arkoseDataBlob", "string"), 6: ("publicCaseId", "string"), 7: ("suppressed", "int32")},
    "SelfieChallengeBan": {1: ("selfieChallengeToken", "string"), 2: ("selfieStatus", "string"),
                          3: ("refreshToken", "string")},
    "IdvChallengeBan": {1: ("idvChallengeToken", "string"), 2: ("refreshToken", "string"),
                       3: ("idvStatus", "int32")},
    "GetPhoneState": {1: ("refreshToken", "w:string")},
    "ValidatePhoneOtpState": {1: ("refreshToken", "w:string"), 2: ("phone", "string"),
                              3: ("otpLength", "w:int32"), 4: ("smsSent", "w:bool")},
    "EmailMarketing": {2: ("showMarketingOptIn", "w:bool"), 3: ("showStrictOptIn", "w:bool"),
                       4: ("checkedByDefault", "w:bool")},
    "GetEmailState": {1: ("refreshToken", "w:string"), 2: ("emailMarketing", "EmailMarketing")},
    "ValidateEmailOtpState": {1: ("refreshToken", "w:string"), 2: ("unmaskedEmail", "string"),
                              3: ("maskedEmail", "string"), 4: ("otpLength", "w:int32"),
                              5: ("emailSent", "w:bool"), 6: ("emailMarketing", "EmailMarketing"),
                              7: ("newAccountAllowed", "w:bool"), 8: ("accountRecoveryAllowed", "w:bool")},
    "OnboardingState": {1: ("refreshToken", "string"), 2: ("onboardingToken", "string"),
                        3: ("userId", "w:string")},
    "LoginResult": {1: ("refreshToken", "string"), 2: ("authToken", "string"), 3: ("captcha", "int32"),
                    4: ("userId", "string"), 5: ("authTokenTtl", "w:int64"),
                    7: ("updatedEmailAddress", "w:string")},
    "SocialConnectionList": {1: ("refreshToken", "w:string"), 2: ("connections", "SocialConnection[]")},
    "SocialConnection": {1: ("service", "int32")},
    "AppleAccountNotFound": {1: ("willLink", "bool"), 2: ("refreshToken", "w:string")},
    "ValidateEmailMagicLinkOtpState": {},
    "ValidateFacebookState": {1: ("refreshToken", "w:string"), 2: ("maskedEmail", "w:string")},
    "ValidateGoogleState": {1: ("refreshToken", "w:string"), 2: ("maskedEmail", "w:string")},
    "FacebookAccountNotFound": {1: ("refreshToken", "w:string"), 2: ("maskedEmail", "w:string")},
    "GoogleAccountNotFound": {1: ("refreshToken", "w:string"), 2: ("maskedEmail", "w:string")},
    "CaptchaState": {1: ("referenceToken", "string"), 2: ("captchaPublicKey", "string"), 3: ("dataBlob", "string")},
    "LineAccountNotFound": {1: ("refreshToken", "w:string")},
    "ValidateExistingPhoneState": {1: ("refreshToken", "w:string"), 2: ("maskedPhoneNumber", "w:string"),
                                   3: ("otpLength", "w:int32"), 4: ("smsSent", "w:bool"),
                                   5: ("accountRecoveryAllowed", "w:bool")},
    "TemporaryLoginResult": {1: ("authToken", "w:string"), 2: ("authTokenTtl", "w:int64")},
    "IneligibleEmail": {1: ("refreshToken", "w:string")},
    "AuthGatewayResponse": {
        1: ("meta", "MetaProto"), 2: ("error", "ErrorProto"),
        3: ("getPhoneState", "GetPhoneState"), 4: ("validatePhoneOtpState", "ValidatePhoneOtpState"),
        5: ("getEmailState", "GetEmailState"), 6: ("validateEmailOtpState", "ValidateEmailOtpState"),
        7: ("onboardingState", "OnboardingState"), 8: ("loginResult", "LoginResult"),
        9: ("socialConnectionList", "SocialConnectionList"), 10: ("appleAccountNotFound", "AppleAccountNotFound"),
        11: ("validateEmailMagicLinkOtpState", "ValidateEmailMagicLinkOtpState"),
        12: ("validateFacebookState", "ValidateFacebookState"), 13: ("validateGoogleState", "ValidateGoogleState"),
        14: ("facebookAccountNotFound", "FacebookAccountNotFound"),
        15: ("googleAccountNotFound", "GoogleAccountNotFound"), 16: ("captchaState", "CaptchaState"),
        17: ("lineAccountNotFound", "LineAccountNotFound"),
        18: ("validateExistingPhoneState", "ValidateExistingPhoneState"),
        19: ("temporaryLoginResult", "TemporaryLoginResult"), 20: ("ineligibleEmail", "IneligibleEmail"),
        21: ("authFlowVariant", "w:string"),
    },
}

REQUEST_FACTORS = {
    "phone": (1, "Phone"), "phoneOtp": (2, "PhoneOtp"), "email": (3, "Email"),
    "emailOtp": (5, "EmailOtp"), "phoneOtpResend": (7, "PhoneOtpResend"),
    "emailOtpResend": (8, "EmailOtpResend"), "getInitialState": (9, "GetInitialState"),
    "refreshAuth": (10, "RefreshAuth"), "dismissSocialConnectionList": (12, "DismissSocialConnectionList"),
    "captcha": (18, "Captcha"), "existingPhoneOtp": (19, "ExistingPhoneOTP"),
    "existingPhoneOtpResend": (20, "ExistingPhoneOTPResend"),
    "preEmail": (24, "PreEmail"),
}
RESPONSE_STATES = frozenset(value[0] for number, value in SCHEMAS["AuthGatewayResponse"].items() if 3 <= number <= 20)
PRIMITIVES = {"string", "int32", "int64", "bool"}


def _varint(value):
    if value < 0:
        value &= (1 << 64) - 1
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _read_varint(raw, position):
    value = 0
    for index in range(10):
        if position >= len(raw):
            raise CodecError("Truncated protobuf varint.")
        byte = raw[position]
        position += 1
        if index == 9 and byte > 1:
            raise CodecError("Protobuf varint exceeds 64 bits.")
        value |= (byte & 127) << (7 * index)
        if not byte & 128:
            return value, position
    raise CodecError("Invalid protobuf varint.")


def _fields(raw):
    position = 0
    while position < len(raw):
        tag, position = _read_varint(raw, position)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number <= 536870911:
            raise CodecError("Invalid protobuf field number.")
        if wire == 0:
            value, position = _read_varint(raw, position)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, position = _read_varint(raw, position)
            else:
                length = 8 if wire == 1 else 4
            end = position + length
            if end > len(raw):
                raise CodecError("Truncated protobuf field.")
            value, position = raw[position:end], end
        else:
            raise CodecError("Unsupported protobuf wire type.")
        yield number, wire, value


def _encode_value(number, kind, value):
    if kind.startswith("w:"):
        data = _encode_value(1, kind[2:], value)
    elif kind in SCHEMAS:
        data = _encode_message(kind, value)
    elif kind == "string":
        if not isinstance(value, str):
            raise CodecError("A protobuf string field requires a string.")
        data = value.encode("utf-8")
    else:
        if kind == "bool":
            if not isinstance(value, bool):
                raise CodecError("A protobuf boolean field requires a boolean.")
            value = int(value)
        elif kind in ("int32", "int64"):
            bits = 32 if kind == "int32" else 64
            if isinstance(value, bool) or not isinstance(value, int) or not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
                raise CodecError("A protobuf integer field is outside its signed range.")
        else:
            raise CodecError("Unsupported protobuf field type.")
        return _varint(number << 3) + _varint(value)
    return _varint((number << 3) | 2) + _varint(len(data)) + data


def _encode_message(name, values):
    if not isinstance(values, dict):
        raise CodecError("A protobuf message requires a dictionary.")
    schema = SCHEMAS[name]
    known = {field_name for field_name, _ in schema.values()}
    if values.keys() - known:
        raise CodecError("Unknown fields for " + name + ".")
    if name in ("Phone", "PhoneOtpResend"):
        checks = {"captchaToken", "iosDeviceToken", "androidJws"} if name == "Phone" else {"iosDeviceToken", "androidJws"}
        if sum(values.get(key) is not None for key in checks) > 1:
            raise CodecError("Only one phone device-check field may be supplied.")
    result = bytearray()
    for number, (field_name, kind) in schema.items():
        value = values.get(field_name)
        if value is None:
            continue
        if kind.endswith("[]"):
            if not isinstance(value, list):
                raise CodecError("A repeated protobuf field requires a list.")
            for item in value:
                result.extend(_encode_value(number, kind[:-2], item))
        else:
            result.extend(_encode_value(number, kind, value))
    return bytes(result)


def _decode_value(kind, wire, value):
    expected_wire = 0 if kind in {"int32", "int64", "bool"} else 2
    if wire != expected_wire:
        raise CodecError("Unexpected protobuf wire type for a known field.")
    if kind.startswith("w:"):
        primitive = kind[2:]
        result = "" if primitive == "string" else False if primitive == "bool" else 0
        for number, inner_wire, inner_value in _fields(value):
            if number == 1:
                result = _decode_value(primitive, inner_wire, inner_value)
        return result
    if kind in SCHEMAS:
        return _decode_message(kind, value)
    if kind == "string":
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CodecError("Invalid UTF-8 in protobuf string.") from error
    if kind == "bool":
        return bool(value)
    if kind in {"int32", "int64"}:
        bits = 32 if kind == "int32" else 64
        value &= (1 << bits) - 1
        return value - (1 << bits) if value >= (1 << (bits - 1)) else value
    raise CodecError("Unsupported protobuf field type.")


def _decode_message(name, raw):
    result = {}
    unknown = []
    for number, wire, value in _fields(raw):
        entry = SCHEMAS[name].get(number)
        if entry is None:
            unknown.append(number)
            continue
        field_name, kind = entry
        repeated = kind.endswith("[]")
        decoded = _decode_value(kind[:-2] if repeated else kind, wire, value)
        if name == "AuthGatewayResponse" and field_name in RESPONSE_STATES:
            for sibling in RESPONSE_STATES:
                result.pop(sibling, None)
        if repeated:
            result.setdefault(field_name, []).append(decoded)
        else:
            result[field_name] = decoded
    if name == "AuthGatewayResponse" and unknown:
        result["_unknownFields"] = sorted(set(unknown))
    return result


def encode_request(factor, data, auth_flow_variant=None):
    """Encode one observed login factor; values use plain scalars for wrappers.

    auth_flow_variant, when provided, is the envelope's wrapped string field 23.
    No request defaults, credentials, or device attestations are invented.
    """
    if factor not in REQUEST_FACTORS:
        raise CodecError("Unsupported authentication factor.")
    number, message_name = REQUEST_FACTORS[factor]
    result = _encode_value(number, message_name, data)
    if auth_flow_variant is not None:
        result += _encode_value(23, "w:string", auth_flow_variant)
    return result


def decode_response(raw):
    """Decode the gateway response without logging it.

    Absent fields stay absent. Present empty scalar wrappers decode to their
    protobuf defaults. Unknown top-level field numbers appear in _unknownFields;
    their payloads are discarded. Enums remain numeric. For a response with
    multiple known state factors, the last one wins, following protobuf oneof.
    """
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise CodecError("A protobuf response must be bytes.")
    return _decode_message("AuthGatewayResponse", bytes(raw))
